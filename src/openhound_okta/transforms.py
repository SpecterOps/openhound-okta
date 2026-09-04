import dlt
import duckdb

from openhound_okta.saml_eligibility import configured_saml_eligibility_preflight


USERS_ID_INDEX_NAME = "users_id_idx"


def _has_saml_eligibility_preflight_marker(
    con: duckdb.DuckDBPyConnection,
    schema: str,
) -> bool:
    """Return whether collection marked this raw snapshot for preflight.

    DLT's preprocessing transformer can execute outside the source-specific
    configuration context, so a CLI environment flag is not always visible
    here. The marker is emitted only by an explicitly enabled collection and
    makes the resulting raw snapshot self-describing.
    """

    return bool(
        con.execute(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = ?
              AND table_name = 'groups'
              AND column_name = 'saml_membership_expected_count'
            """,
            [schema],
        ).fetchone()
    )


def ensure_users_id_index(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> bool:
    """Create the non-unique users(id) lookup index when it is absent."""

    rows = con.execute(
        """
        SELECT schema_name, table_name, index_name, is_unique, expressions
        FROM duckdb_indexes()
        WHERE schema_name = ? AND index_name = ?
        ORDER BY schema_name, table_name
        """,
        [schema, USERS_ID_INDEX_NAME],
    ).fetchall()
    if rows:
        expected = (schema, "users", USERS_ID_INDEX_NAME, False, "[id]")
        if rows != [expected]:
            raise RuntimeError(
                f"incompatible DuckDB index named {USERS_ID_INDEX_NAME!r}: {rows!r}"
            )
        return False

    quoted_schema = schema.replace('"', '""')
    con.execute(f'CREATE INDEX {USERS_ID_INDEX_NAME} ON "{quoted_schema}".users(id)')
    return True


def principals_with_admin_roles(con, schema: str = "okta") -> None:
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.principals_with_admin_roles (
            id VARCHAR,
            principal_type VARCHAR
        )
    """)


def insert_principals_with_admin_roles(
    con,
    schema: str = "okta",
) -> None:
    principals = [
        f"""SELECT DISTINCT id, 'user' AS principal_type
            FROM {schema}.privileged_users""",
        f"""SELECT source_id AS id, 'user' AS principal_type
            FROM {schema}.user_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'USER'""",
        f"""SELECT source_id AS id, 'group' AS principal_type
            FROM {schema}.group_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'GROUP'""",
        f"""SELECT source_id AS id, 'client' AS principal_type
            FROM {schema}.client_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'CLIENT'""",
    ]
    for principal in principals:
        try:
            con.execute(f"""
                INSERT INTO {schema}.principals_with_admin_roles
                {principal}
                """)
        except duckdb.CatalogException:
            pass

        except Exception as e:
            raise e

    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.principals_with_admin_roles AS
        SELECT DISTINCT id, principal_type
        FROM {schema}.principals_with_admin_roles
    """)


def non_admin_users(con, schema: str = "okta") -> None:
    """Users with no role assignment"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_users AS
        SELECT id FROM {schema}.users
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'user'
        )
    """)


def non_admin_groups(con, schema: str = "okta") -> None:
    """Groups with no role assignment"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_groups AS
        SELECT id FROM {schema}.groups
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'group'
        )
    """)


def non_admin_apps(con, schema: str = "okta") -> None:
    """Applications with no role assignment"""
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_apps AS
        SELECT id FROM {schema}.applications
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'client'
        )
    """)


def _require_saml_eligibility_preflight_inputs(
    con: duckdb.DuckDBPyConnection,
    schema: str,
) -> None:
    """Reject old or partial raw snapshots before they could resemble proof."""

    required_columns = {
        "group_assigned_apps": {
            "id",
            "group_id",
            "status",
            "app_sign_on_mode",
            "assignment_profile",
        },
        "groups": {"id", "saml_membership_expected_count"},
        "group_memberships": {"id", "group_id"},
        "users": {"id", "status", "profile"},
        "application_users": {"app_id", "id", "status", "scope"},
        "saml_claim_mappings": {
            "app_id",
            "source_property",
            "expression",
            "claim_type",
            "format",
        },
    }
    rows = con.execute(
        """
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = ?
        """,
        [schema],
    ).fetchall()
    available: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        available.setdefault(table_name, set()).add(column_name)

    missing = {
        table_name: sorted(columns - available.get(table_name, set()))
        for table_name, columns in required_columns.items()
        if columns - available.get(table_name, set())
    }
    if missing:
        details = "; ".join(
            f"{table_name}: {', '.join(columns)}"
            for table_name, columns in sorted(missing.items())
        )
        raise RuntimeError(
            "SAML eligibility preflight requires a fresh complete Okta snapshot; "
            f"missing raw columns: {details}"
        )


def create_saml_eligibility_preflight(
    con: duckdb.DuckDBPyConnection,
    schema: str = "okta",
) -> None:
    """Build the opt-in, value-free proof ledger for later v0.4 compactability.

    The ledger is producer-local evidence consumed only in development shadow
    mode. It can prove static policy evaluation and a fixed inherited-support
    exception inventory, but it never removes the existing expanded facts.
    """

    _require_saml_eligibility_preflight_inputs(con, schema)

    con.execute(
        f"""
        CREATE OR REPLACE TABLE {schema}.saml_eligibility_preflight AS
        WITH assignments AS (
            SELECT
                id AS app_id,
                group_id,
                max(status) AS app_status,
                max(app_sign_on_mode) AS app_sign_on_mode,
                max(COALESCE(CAST(assignment_profile AS VARCHAR), ''))
                    AS assignment_profile
            FROM {schema}.group_assigned_apps
            GROUP BY id, group_id
        ),
        partitions AS (
            SELECT
                app_id,
                string_agg(group_id, ',' ORDER BY group_id) AS assigned_group_ids,
                count(*) AS assigned_group_count,
                bool_and(app_status = 'ACTIVE' AND app_sign_on_mode = 'SAML_2_0')
                    AS active_saml_application,
                bool_and(
                    assignment_profile IN ('', 'null', '{{}}')
                ) AS supported_assignment_profile
            FROM assignments
            GROUP BY app_id
        ),
        group_coverage AS (
            SELECT
                assignments.app_id,
                assignments.group_id,
                max(groups.saml_membership_expected_count) AS expected_member_count,
                count(group_memberships.id) AS raw_member_row_count,
                count(DISTINCT group_memberships.id) AS distinct_member_count,
                count(DISTINCT groups.id) AS resolved_group_count
            FROM assignments
            LEFT JOIN {schema}.groups AS groups ON groups.id = assignments.group_id
            LEFT JOIN {schema}.group_memberships AS group_memberships
                ON group_memberships.group_id = assignments.group_id
            GROUP BY assignments.app_id, assignments.group_id
        ),
        group_coverage_by_partition AS (
            SELECT
                app_id,
                bool_and(
                    resolved_group_count = 1
                    AND expected_member_count IS NOT NULL
                    AND raw_member_row_count = distinct_member_count
                    AND distinct_member_count = expected_member_count
                ) AS membership_complete,
                sum(
                    CASE
                        WHEN resolved_group_count <> 1 THEN 1
                        ELSE 0
                    END
                ) AS unresolved_group_count,
                sum(
                    CASE
                        WHEN expected_member_count IS NULL
                            OR raw_member_row_count <> distinct_member_count
                            OR distinct_member_count <> expected_member_count
                        THEN 1
                        ELSE 0
                    END
                ) AS membership_reconciliation_failure_count
            FROM group_coverage
            GROUP BY app_id
        ),
        predicted_members AS (
            SELECT DISTINCT
                assignments.app_id,
                group_memberships.id AS user_id,
                users.status AS user_status
            FROM assignments
            JOIN {schema}.group_memberships AS group_memberships
                ON group_memberships.group_id = assignments.group_id
            LEFT JOIN {schema}.users AS users ON users.id = group_memberships.id
        ),
        reachability AS (
            SELECT
                app_id,
                bool_and(COALESCE(user_status IN (
                    'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY',
                    'LOCKED_OUT', 'SUSPENDED', 'DEPROVISIONED', 'STAGED'
                ), FALSE)) AS reachability_complete,
                sum(
                    CASE
                        WHEN user_status NOT IN (
                            'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY',
                            'LOCKED_OUT', 'SUSPENDED', 'DEPROVISIONED', 'STAGED'
                        ) OR user_status IS NULL
                        THEN 1
                        ELSE 0
                    END
                ) AS unknown_or_missing_user_count,
                count(*) FILTER (
                    WHERE user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    )
                ) AS predicted_eligible_user_count,
                sha256(COALESCE(string_agg(
                    user_id ORDER BY user_id
                ) FILTER (
                    WHERE user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    )
                ), '')) AS predicted_eligible_user_digest
            FROM predicted_members
            GROUP BY app_id
        ),
        observed_group_rows AS (
            SELECT
                app_id,
                id AS user_id,
                max(status) AS application_user_status,
                count(*) AS application_user_row_count
            FROM {schema}.application_users
            WHERE scope = 'GROUP'
            GROUP BY app_id, id
        ),
        observed_group_users AS (
            SELECT
                observed_group_rows.app_id,
                observed_group_rows.user_id,
                observed_group_rows.application_user_status,
                observed_group_rows.application_user_row_count,
                users.status AS user_status
            FROM observed_group_rows
            LEFT JOIN {schema}.users AS users
                ON users.id = observed_group_rows.user_id
        ),
        observed_effective AS (
            SELECT
                app_id,
                count(*) FILTER (
                    WHERE application_user_status IN ('ACTIVE', 'PROVISIONED')
                        AND user_status IN (
                            'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                        )
                ) AS observed_eligible_user_count,
                sha256(COALESCE(string_agg(
                    user_id ORDER BY user_id
                ) FILTER (
                    WHERE application_user_status IN ('ACTIVE', 'PROVISIONED')
                        AND user_status IN (
                            'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                        )
                ), '')) AS observed_eligible_user_digest,
                sum(
                    CASE
                        WHEN application_user_status IS NULL OR user_status IS NULL
                        THEN 1
                        ELSE 0
                    END
                ) AS unresolved_observed_user_count
            FROM observed_group_users
            GROUP BY app_id
        ),
        exclusion_reconciliation AS (
            SELECT
                coalesce(predicted_members.app_id, observed_group_users.app_id)
                    AS app_id,
                sum(CASE
                    WHEN predicted_members.user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    ) AND (
                        observed_group_users.user_id IS NULL
                        OR observed_group_users.application_user_row_count <> 1
                    ) THEN 1 ELSE 0 END
                ) AS missing_or_duplicate_group_assignment_count,
                sum(CASE
                    WHEN predicted_members.user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    )
                    AND observed_group_users.application_user_row_count = 1
                    AND observed_group_users.application_user_status NOT IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY',
                        'LOCKED_OUT', 'SUSPENDED', 'DEPROVISIONED', 'STAGED'
                    ) THEN 1 ELSE 0 END
                ) AS unknown_application_user_status_count,
                sum(CASE
                    WHEN predicted_members.user_id IS NULL
                    AND observed_group_users.user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    ) THEN 1 ELSE 0 END
                ) AS unexpected_enabled_group_assignment_count,
                sum(CASE
                    WHEN observed_group_users.user_id IS NOT NULL
                    AND observed_group_users.user_status IS NULL
                    THEN 1 ELSE 0 END
                ) AS unresolved_observed_user_count,
                sum(CASE
                    WHEN predicted_members.user_status IN (
                        'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
                    )
                    AND observed_group_users.application_user_row_count = 1
                    AND observed_group_users.application_user_status IN (
                        'PASSWORD_EXPIRED', 'RECOVERY', 'LOCKED_OUT', 'SUSPENDED',
                        'DEPROVISIONED', 'STAGED'
                    ) THEN 1 ELSE 0 END
                ) AS fixed_inherited_exception_count
            FROM predicted_members
            FULL OUTER JOIN observed_group_users
                ON observed_group_users.app_id = predicted_members.app_id
                AND observed_group_users.user_id = predicted_members.user_id
            GROUP BY coalesce(predicted_members.app_id, observed_group_users.app_id)
        ),
        unsupported_scopes AS (
            SELECT
                app_id,
                count(*) AS unsupported_scope_count
            FROM {schema}.application_users
            WHERE scope IS NULL OR scope NOT IN ('GROUP', 'USER')
            GROUP BY app_id
        ),
        claims AS (
            SELECT
                saml_claim_mappings.app_id,
                count(*) AS claim_mapping_count,
                bool_and(
                    source_property IN (
                        'source.login', 'user.login', 'source.email', 'user.email',
                        'source.firstName', 'user.firstName',
                        'source.lastName', 'user.lastName',
                        'source.department', 'user.department', 'source.city', 'user.city',
                        'source.state', 'user.state',
                        'source.countryCode', 'user.countryCode',
                        'source.organization', 'user.organization', 'source.title', 'user.title',
                        'source.userType', 'user.userType',
                        'source.employeeNumber', 'user.employeeNumber',
                        'source.division', 'user.division', 'source.managerId', 'user.managerId'
                    )
                    AND trim(expression) IN (
                        source_property,
                        chr(36) || chr(123) || source_property || chr(125)
                    )
                    AND (
                        claim_type <> 'name_id'
                        OR format <> 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
                        OR source_property IN (
                            'source.login', 'user.login', 'source.email', 'user.email'
                        )
                    )
                ) AS supported_claim_inventory
            FROM {schema}.saml_claim_mappings
            GROUP BY saml_claim_mappings.app_id
        ),
        supported_claim_mappings AS (
            SELECT
                app_id,
                split_part(source_property, '.', 2) AS profile_field
            FROM {schema}.saml_claim_mappings
            WHERE source_property IN (
                'source.login', 'user.login', 'source.email', 'user.email',
                'source.firstName', 'user.firstName',
                'source.lastName', 'user.lastName',
                'source.department', 'user.department', 'source.city', 'user.city',
                'source.state', 'user.state', 'source.countryCode', 'user.countryCode',
                'source.organization', 'user.organization', 'source.title', 'user.title',
                'source.userType', 'user.userType',
                'source.employeeNumber', 'user.employeeNumber',
                'source.division', 'user.division', 'source.managerId', 'user.managerId'
            )
            AND trim(expression) IN (
                source_property,
                chr(36) || chr(123) || source_property || chr(125)
            )
        ),
        claim_value_failures AS (
            SELECT
                predicted_members.app_id,
                count(*) AS missing_claim_value_count
            FROM predicted_members
            JOIN supported_claim_mappings
                ON supported_claim_mappings.app_id = predicted_members.app_id
            JOIN {schema}.users AS users ON users.id = predicted_members.user_id
            WHERE predicted_members.user_status IN (
                'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
            )
            AND coalesce(nullif(trim(CASE supported_claim_mappings.profile_field
                WHEN 'login' THEN json_extract_string(users.profile, '$.login')
                WHEN 'email' THEN json_extract_string(users.profile, '$.email')
                WHEN 'firstName' THEN json_extract_string(users.profile, '$.firstName')
                WHEN 'lastName' THEN json_extract_string(users.profile, '$.lastName')
                WHEN 'department' THEN json_extract_string(users.profile, '$.department')
                WHEN 'city' THEN json_extract_string(users.profile, '$.city')
                WHEN 'state' THEN json_extract_string(users.profile, '$.state')
                WHEN 'countryCode' THEN json_extract_string(users.profile, '$.countryCode')
                WHEN 'organization' THEN json_extract_string(users.profile, '$.organization')
                WHEN 'title' THEN json_extract_string(users.profile, '$.title')
                WHEN 'userType' THEN json_extract_string(users.profile, '$.userType')
                WHEN 'employeeNumber' THEN json_extract_string(users.profile, '$.employeeNumber')
                WHEN 'division' THEN json_extract_string(users.profile, '$.division')
                WHEN 'managerId' THEN json_extract_string(users.profile, '$.managerId')
                ELSE NULL
            END), ''), '') = ''
            GROUP BY predicted_members.app_id
        )
        SELECT
            partitions.app_id,
            partitions.assigned_group_ids,
            sha256(partitions.assigned_group_ids) AS policy_digest,
            partitions.assigned_group_count,
            COALESCE(reachability.predicted_eligible_user_count, 0)
                AS predicted_eligible_user_count,
            COALESCE(observed_effective.observed_eligible_user_count, 0)
                AS observed_eligible_user_count,
            COALESCE(reachability.predicted_eligible_user_digest, sha256(''))
                AS predicted_eligible_user_digest,
            COALESCE(observed_effective.observed_eligible_user_digest, sha256(''))
                AS observed_eligible_user_digest,
            CASE WHEN group_coverage_by_partition.membership_complete
                THEN 'complete' ELSE 'incomplete' END AS membership_coverage,
            CASE WHEN COALESCE(reachability.reachability_complete, TRUE)
                THEN 'complete' ELSE 'incomplete' END AS principal_reachability_coverage,
            CASE
                WHEN group_coverage_by_partition.membership_complete
                    AND COALESCE(reachability.reachability_complete, TRUE)
                    AND COALESCE(unsupported_scopes.unsupported_scope_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unresolved_observed_user_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.missing_or_duplicate_group_assignment_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unknown_application_user_status_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unexpected_enabled_group_assignment_count, 0) = 0
                THEN 'complete'
                ELSE 'incomplete'
            END AS principal_exclusion_coverage,
            CASE
                WHEN partitions.active_saml_application
                    AND partitions.supported_assignment_profile
                THEN 'complete'
                ELSE 'incomplete'
            END AS policy_evaluation_coverage,
            CASE
                WHEN COALESCE(claims.claim_mapping_count, 0) > 0
                    AND COALESCE(claims.supported_claim_inventory, FALSE)
                    AND COALESCE(claim_value_failures.missing_claim_value_count, 0) = 0
                THEN 'complete'
                ELSE 'incomplete'
            END AS claim_evidence_coverage,
            COALESCE(group_coverage_by_partition.unresolved_group_count, 0)
                AS unresolved_group_count,
            COALESCE(group_coverage_by_partition.membership_reconciliation_failure_count, 0)
                AS membership_reconciliation_failure_count,
            COALESCE(reachability.unknown_or_missing_user_count, 0)
                AS unknown_or_missing_user_count,
            COALESCE(exclusion_reconciliation.unresolved_observed_user_count, 0)
                AS unresolved_observed_user_count,
            COALESCE(exclusion_reconciliation.missing_or_duplicate_group_assignment_count, 0)
                AS missing_or_duplicate_group_assignment_count,
            COALESCE(exclusion_reconciliation.unknown_application_user_status_count, 0)
                AS unknown_application_user_status_count,
            COALESCE(exclusion_reconciliation.unexpected_enabled_group_assignment_count, 0)
                AS unexpected_enabled_group_assignment_count,
            COALESCE(exclusion_reconciliation.fixed_inherited_exception_count, 0)
                AS fixed_inherited_exception_count,
            COALESCE(unsupported_scopes.unsupported_scope_count, 0)
                AS unsupported_scope_count,
            COALESCE(claim_value_failures.missing_claim_value_count, 0)
                AS missing_claim_value_count,
            CASE
                WHEN group_coverage_by_partition.membership_complete
                    AND COALESCE(reachability.reachability_complete, TRUE)
                    AND COALESCE(unsupported_scopes.unsupported_scope_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unresolved_observed_user_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.missing_or_duplicate_group_assignment_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unknown_application_user_status_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unexpected_enabled_group_assignment_count, 0) = 0
                    AND partitions.active_saml_application
                    AND partitions.supported_assignment_profile
                    AND COALESCE(claims.claim_mapping_count, 0) > 0
                    AND COALESCE(claims.supported_claim_inventory, FALSE)
                    AND COALESCE(claim_value_failures.missing_claim_value_count, 0) = 0
                THEN 'candidate_complete'
                WHEN group_coverage_by_partition.membership_complete
                    AND COALESCE(reachability.reachability_complete, TRUE)
                    AND COALESCE(unsupported_scopes.unsupported_scope_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unresolved_observed_user_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.missing_or_duplicate_group_assignment_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unknown_application_user_status_count, 0) = 0
                    AND COALESCE(exclusion_reconciliation.unexpected_enabled_group_assignment_count, 0) = 0
                    AND partitions.active_saml_application
                    AND partitions.supported_assignment_profile
                THEN 'eligibility_candidate_complete'
                ELSE 'incomplete'
            END AS preflight_classification,
            concat_ws(
                ',',
                CASE WHEN COALESCE(group_coverage_by_partition.unresolved_group_count, 0) > 0
                    THEN 'unresolved_group' END,
                CASE WHEN COALESCE(group_coverage_by_partition.membership_reconciliation_failure_count, 0) > 0
                    THEN 'membership_count_mismatch' END,
                CASE WHEN COALESCE(reachability.unknown_or_missing_user_count, 0) > 0
                    THEN 'unknown_or_missing_user' END,
                CASE WHEN COALESCE(exclusion_reconciliation.unresolved_observed_user_count, 0) > 0
                    THEN 'unresolved_observed_user' END,
                CASE WHEN COALESCE(exclusion_reconciliation.unknown_application_user_status_count, 0) > 0
                    THEN 'unknown_application_user_status' END,
                CASE WHEN COALESCE(unsupported_scopes.unsupported_scope_count, 0) > 0
                    THEN 'unsupported_assignment_scope' END,
                CASE WHEN COALESCE(exclusion_reconciliation.missing_or_duplicate_group_assignment_count, 0) > 0
                    OR COALESCE(exclusion_reconciliation.unexpected_enabled_group_assignment_count, 0) > 0
                    THEN 'group_scope_set_mismatch' END,
                CASE WHEN NOT partitions.active_saml_application
                    THEN 'unsupported_application_policy' END,
                CASE WHEN NOT partitions.supported_assignment_profile
                    THEN 'unsupported_assignment_profile' END,
                CASE WHEN COALESCE(claims.claim_mapping_count, 0) = 0
                    THEN 'missing_claim_inventory' END,
                CASE WHEN NOT COALESCE(claims.supported_claim_inventory, FALSE)
                    THEN 'unsupported_claim_mapping' END,
                CASE WHEN COALESCE(claim_value_failures.missing_claim_value_count, 0) > 0
                    THEN 'missing_projected_claim_value' END
            ) AS reason_codes
        FROM partitions
        LEFT JOIN group_coverage_by_partition
            ON group_coverage_by_partition.app_id = partitions.app_id
        LEFT JOIN reachability ON reachability.app_id = partitions.app_id
        LEFT JOIN observed_effective ON observed_effective.app_id = partitions.app_id
        LEFT JOIN exclusion_reconciliation
            ON exclusion_reconciliation.app_id = partitions.app_id
        LEFT JOIN unsupported_scopes ON unsupported_scopes.app_id = partitions.app_id
        LEFT JOIN claims ON claims.app_id = partitions.app_id
        LEFT JOIN claim_value_failures
            ON claim_value_failures.app_id = partitions.app_id
        """
    )
    con.execute(
        f"""
        CREATE OR REPLACE TABLE {schema}.saml_eligibility_preflight_exceptions AS
        WITH observed_group_rows AS (
            SELECT
                app_id,
                id AS user_id,
                max(status) AS application_user_status,
                count(*) AS application_user_row_count
            FROM {schema}.application_users
            WHERE scope = 'GROUP'
            GROUP BY app_id, id
        ),
        assigned_members AS (
            SELECT DISTINCT
                group_assigned_apps.id AS app_id,
                group_memberships.id AS user_id
            FROM {schema}.group_assigned_apps
            JOIN {schema}.group_memberships
                ON group_memberships.group_id = group_assigned_apps.group_id
        )
        SELECT
            observed_group_rows.app_id,
            observed_group_rows.user_id
        FROM observed_group_rows
        JOIN assigned_members
            ON assigned_members.app_id = observed_group_rows.app_id
            AND assigned_members.user_id = observed_group_rows.user_id
        JOIN {schema}.users ON users.id = observed_group_rows.user_id
        JOIN {schema}.saml_eligibility_preflight AS ledger
            ON ledger.app_id = observed_group_rows.app_id
        WHERE observed_group_rows.application_user_row_count = 1
          AND observed_group_rows.application_user_status IN (
              'PASSWORD_EXPIRED', 'RECOVERY', 'LOCKED_OUT', 'SUSPENDED',
              'DEPROVISIONED', 'STAGED'
          )
          AND users.status IN (
              'ACTIVE', 'PROVISIONED', 'PASSWORD_EXPIRED', 'RECOVERY'
          )
          AND ledger.membership_coverage = 'complete'
          AND ledger.principal_reachability_coverage = 'complete'
          AND ledger.principal_exclusion_coverage = 'complete'
          AND ledger.policy_evaluation_coverage = 'complete'
        """
    )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    principals_with_admin_roles(con, schema)
    insert_principals_with_admin_roles(con, schema)
    non_admin_users(con, schema)
    non_admin_groups(con, schema)
    non_admin_apps(con, schema)
    ensure_users_id_index(con, schema)
    if configured_saml_eligibility_preflight(
        dlt.config.get
    ) or _has_saml_eligibility_preflight_marker(con, schema):
        create_saml_eligibility_preflight(con, schema)
