import duckdb
import pytest

from openhound_okta.lookup import OktaLookup
from openhound_okta.transforms import create_saml_eligibility_preflight
from openhound_okta.source import _group_with_saml_membership_expected_count, groups


def _connection() -> duckdb.DuckDBPyConnection:
    connection = duckdb.connect(":memory:")
    connection.execute("CREATE SCHEMA okta")
    connection.execute(
        """
        CREATE TABLE okta.group_assigned_apps (
            id VARCHAR,
            group_id VARCHAR,
            status VARCHAR,
            app_sign_on_mode VARCHAR,
            assignment_priority INTEGER,
            assignment_profile JSON
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE okta.groups (
            id VARCHAR,
            saml_membership_expected_count INTEGER
        )
        """
    )
    connection.execute(
        "CREATE TABLE okta.group_memberships (id VARCHAR, group_id VARCHAR)"
    )
    connection.execute(
        "CREATE TABLE okta.users (id VARCHAR, status VARCHAR, profile JSON)"
    )
    connection.execute(
        """
        CREATE TABLE okta.application_users (
            app_id VARCHAR,
            id VARCHAR,
            status VARCHAR,
            scope VARCHAR
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE okta.saml_claim_mappings (
            app_id VARCHAR,
            source_property VARCHAR,
            expression VARCHAR,
            claim_type VARCHAR,
            format VARCHAR
        )
        """
    )
    connection.execute(
        """
        INSERT INTO okta.group_assigned_apps VALUES
            ('app-1', 'group-1', 'ACTIVE', 'SAML_2_0', 0, NULL),
            ('app-1', 'group-2', 'ACTIVE', 'SAML_2_0', 0, NULL)
        """
    )
    connection.execute("INSERT INTO okta.groups VALUES ('group-1', 2), ('group-2', 1)")
    connection.execute(
        """
        INSERT INTO okta.group_memberships VALUES
            ('user-1', 'group-1'),
            ('user-2', 'group-1'),
            ('user-2', 'group-2')
        """
    )
    connection.execute(
        """
        INSERT INTO okta.users VALUES
            ('user-1', 'ACTIVE', '{"login":"one@example.test","email":"one@example.test","firstName":"One"}'),
            ('user-2', 'PROVISIONED', '{"login":"two@example.test","email":"two@example.test","firstName":"Two"}'),
            ('direct-user', 'ACTIVE', '{"login":"direct@example.test","email":"direct@example.test","firstName":"Direct"}')
        """
    )
    connection.execute(
        """
        INSERT INTO okta.application_users VALUES
            ('app-1', 'user-1', 'ACTIVE', 'GROUP'),
            ('app-1', 'user-2', 'PROVISIONED', 'GROUP'),
            ('app-1', 'direct-user', 'ACTIVE', 'USER')
        """
    )
    connection.execute(
        """
        INSERT INTO okta.saml_claim_mappings VALUES
            ('app-1', 'source.email', '${source.email}', 'name_id', 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'),
            ('app-1', 'user.firstName', 'user.firstName', 'attribute', NULL)
        """
    )
    return connection


def _ledger(connection: duckdb.DuckDBPyConnection) -> dict[str, object]:
    create_saml_eligibility_preflight(connection)
    columns = [
        row[0]
        for row in connection.execute(
            "DESCRIBE okta.saml_eligibility_preflight"
        ).fetchall()
    ]
    row = connection.execute(
        "SELECT * FROM okta.saml_eligibility_preflight WHERE app_id = 'app-1'"
    ).fetchone()
    assert row is not None
    return dict(zip(columns, row, strict=True))


def test_preflight_marks_a_fully_reconciled_static_partition_candidate_complete():
    connection = _connection()

    ledger = _ledger(connection)

    assert ledger["assigned_group_ids"] == "group-1,group-2"
    assert ledger["predicted_eligible_user_count"] == 2
    assert ledger["observed_eligible_user_count"] == 2
    assert ledger["membership_coverage"] == "complete"
    assert ledger["principal_reachability_coverage"] == "complete"
    assert ledger["principal_exclusion_coverage"] == "complete"
    assert ledger["policy_evaluation_coverage"] == "complete"
    assert ledger["claim_evidence_coverage"] == "complete"
    assert ledger["preflight_classification"] == "candidate_complete"
    assert ledger["reason_codes"] == ""


def test_preflight_ignores_priorities_when_group_assignment_profiles_are_empty():
    connection = _connection()
    connection.execute(
        """
        UPDATE okta.group_assigned_apps
        SET assignment_priority = CASE group_id
            WHEN 'group-1' THEN 3
            WHEN 'group-2' THEN 10
        END,
        assignment_profile = '{}'
        """
    )

    ledger = _ledger(connection)

    assert ledger["policy_evaluation_coverage"] == "complete"
    assert ledger["preflight_classification"] == "candidate_complete"
    assert "unsupported_assignment_priority" not in ledger["reason_codes"]


def test_preflight_rejects_nonempty_group_assignment_profiles_regardless_of_priority():
    connection = _connection()
    connection.execute(
        """
        UPDATE okta.group_assigned_apps
        SET assignment_priority = 10,
            assignment_profile = '{"department":"engineering"}'
        WHERE group_id = 'group-1'
        """
    )

    ledger = _ledger(connection)

    assert ledger["policy_evaluation_coverage"] == "incomplete"
    assert ledger["preflight_classification"] == "incomplete"
    assert "unsupported_assignment_profile" in ledger["reason_codes"]


def test_preflight_fails_closed_when_native_group_scope_disagrees_with_membership():
    connection = _connection()
    connection.execute(
        "DELETE FROM okta.application_users WHERE id = 'user-2' AND scope = 'GROUP'"
    )

    ledger = _ledger(connection)

    assert ledger["membership_coverage"] == "complete"
    assert ledger["principal_exclusion_coverage"] == "incomplete"
    assert ledger["preflight_classification"] == "incomplete"
    assert "group_scope_set_mismatch" in ledger["reason_codes"]


@pytest.mark.parametrize(
    ("sql", "column", "classification"),
    [
        (
            "UPDATE okta.groups SET saml_membership_expected_count = 3 WHERE id = 'group-1'",
            "membership_coverage",
            "incomplete",
        ),
        (
            "UPDATE okta.users SET status = 'FUTURE_STATE' WHERE id = 'user-2'",
            "principal_reachability_coverage",
            "incomplete",
        ),
        (
            "UPDATE okta.saml_claim_mappings SET expression = 'appuser.userName' WHERE source_property = 'source.email'",
            "claim_evidence_coverage",
            "eligibility_candidate_complete",
        ),
    ],
)
def test_preflight_marks_unproven_native_conditions_incomplete(
    sql: str, column: str, classification: str
):
    connection = _connection()
    connection.execute(sql)

    ledger = _ledger(connection)

    assert ledger[column] == "incomplete"
    assert ledger["preflight_classification"] == classification


def test_preflight_proves_a_fixed_group_assignment_exception_without_withholding_the_partition():
    connection = _connection()
    connection.execute(
        "UPDATE okta.application_users SET status = 'STAGED' WHERE id = 'user-2'"
    )

    ledger = _ledger(connection)
    exceptions = connection.execute(
        "SELECT app_id, user_id FROM okta.saml_eligibility_preflight_exceptions"
    ).fetchall()

    assert ledger["principal_exclusion_coverage"] == "complete"
    assert ledger["fixed_inherited_exception_count"] == 1
    assert ledger["preflight_classification"] == "candidate_complete"
    assert exceptions == [("app-1", "user-2")]


def test_lookup_exposes_preflight_ledger_and_exception_inventory():
    connection = _connection()
    connection.execute(
        "UPDATE okta.application_users SET status = 'STAGED' WHERE id = 'user-2'"
    )
    _ledger(connection)
    lookup = OktaLookup(connection)

    ledger = lookup.saml_eligibility_preflight("app-1")

    assert ledger is not None
    assert ledger.policy_evaluability == "static_complete"
    assert lookup.saml_eligibility_exception_applies("app-1", "user-2") is True
    assert lookup.saml_eligibility_exception_applies("app-1", "user-1") is False
    assert lookup._saml_eligibility_exception_inventory.cache_info().misses == 1
    assert lookup._saml_eligibility_exception_inventory.cache_info().hits == 1
    assert lookup.saml_eligibility_preflight("missing") is None


def test_preflight_does_not_treat_a_missing_group_assignment_as_an_exception():
    connection = _connection()
    connection.execute(
        "DELETE FROM okta.application_users WHERE id = 'user-2' AND scope = 'GROUP'"
    )

    ledger = _ledger(connection)
    exceptions = connection.execute(
        "SELECT app_id, user_id FROM okta.saml_eligibility_preflight_exceptions"
    ).fetchall()

    assert ledger["principal_exclusion_coverage"] == "incomplete"
    assert ledger["fixed_inherited_exception_count"] == 0
    assert exceptions == []


def test_preflight_marks_a_missing_source_user_reachability_incomplete():
    connection = _connection()
    connection.execute("DELETE FROM okta.users WHERE id = 'user-2'")

    ledger = _ledger(connection)

    assert ledger["unknown_or_missing_user_count"] == 1
    assert ledger["principal_reachability_coverage"] == "incomplete"
    assert ledger["preflight_classification"] == "incomplete"


def test_preflight_rejects_unknown_application_assignment_scope():
    connection = _connection()
    connection.execute(
        "INSERT INTO okta.application_users VALUES ('app-1', 'unknown-scope', 'ACTIVE', 'RULE')"
    )

    ledger = _ledger(connection)

    assert ledger["unsupported_scope_count"] == 1
    assert ledger["principal_exclusion_coverage"] == "incomplete"
    assert "unsupported_assignment_scope" in ledger["reason_codes"]


def test_preflight_treats_unsupported_claim_sources_as_incomplete_evidence():
    connection = _connection()
    connection.execute(
        """
        INSERT INTO okta.saml_claim_mappings VALUES
            ('app-1', 'appuser.userName', 'appuser.userName', 'attribute', NULL)
        """
    )

    ledger = _ledger(connection)

    assert ledger["claim_evidence_coverage"] == "incomplete"
    assert "unsupported_claim_mapping" in ledger["reason_codes"]


def test_preflight_treats_a_fully_reconciled_empty_group_as_vacuously_reachable():
    connection = _connection()
    connection.execute("DELETE FROM okta.group_memberships")
    connection.execute("DELETE FROM okta.application_users WHERE scope = 'GROUP'")
    connection.execute("UPDATE okta.groups SET saml_membership_expected_count = 0")

    ledger = _ledger(connection)

    assert ledger["membership_coverage"] == "complete"
    assert ledger["principal_reachability_coverage"] == "complete"
    assert ledger["principal_exclusion_coverage"] == "complete"
    assert ledger["preflight_classification"] == "candidate_complete"


def test_preflight_rejects_old_or_partial_raw_snapshots_before_classification():
    connection = _connection()
    connection.execute("ALTER TABLE okta.groups DROP saml_membership_expected_count")

    with pytest.raises(RuntimeError, match="fresh complete Okta snapshot"):
        create_saml_eligibility_preflight(connection)


def test_group_stats_are_projected_without_collecting_another_resource():
    group = {
        "id": "group-1",
        "_embedded": {"stats": {"usersCount": 2}},
    }

    projected = _group_with_saml_membership_expected_count(group)

    assert projected["saml_membership_expected_count"] == 2
    assert projected["_embedded"] is group["_embedded"]


@pytest.mark.parametrize("users_count", (None, -1, "2"))
def test_group_stats_leave_unknown_membership_counts_unprojected(users_count):
    group = {"id": "group-1", "_embedded": {"stats": {"usersCount": users_count}}}

    projected = _group_with_saml_membership_expected_count(group)

    assert projected == group


def test_group_stats_are_added_to_raw_output_only_when_preflight_is_enabled():
    class Pool:
        def paginate(self, *_args, **_kwargs):
            yield [{"id": "group-1", "_embedded": {"stats": {"usersCount": 2}}}]

    disabled = list(
        groups.__wrapped__(
            type("Context", (), {"pool": Pool(), "groups_page_size": 200})()
        )
    )
    enabled = list(
        groups.__wrapped__(
            type(
                "Context",
                (),
                {
                    "pool": Pool(),
                    "groups_page_size": 200,
                    "saml_eligibility_preflight": True,
                },
            )()
        )
    )

    assert disabled == [{"id": "group-1", "_embedded": {"stats": {"usersCount": 2}}}]
    assert enabled[0]["saml_membership_expected_count"] == 2
