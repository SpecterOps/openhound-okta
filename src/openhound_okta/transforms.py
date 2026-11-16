import json
from functools import partial
from typing import Any

import duckdb

from openhound_okta.app_names import AppName
from openhound_okta.saml_aws_account_federation import (
    AwsFederationSettings,
    GroupFilter,
    GroupNameMatch,
    GroupRef,
    plan_group_mapping,
)

USERS_ID_INDEX_NAME = "users_id_idx"


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


# A group name that RE2 (DuckDB) and Java (Okta) can match differently, even
# with a filter in the accepted syntax. RE2 folds U+212A (Kelvin sign) with `k`
# and U+017F (long s) with `s` for letter case, Java does not. `$` matches before
# a final line terminator in Java, but only at the end of the text in RE2.
_UNPROVABLE_NAME_SQL = """
    contains(name, chr(8490)) OR contains(name, chr(383))
    OR ($end_anchored AND right(name, 1) IN (
        chr(10), chr(13), chr(133), chr(8232), chr(8233)))
"""


def group_filter_matches(
    con: duckdb.DuckDBPyConnection, schema: str, group_filter: GroupFilter
) -> list[GroupNameMatch] | None:
    """Match every group name with a Group Filter, in the four ways.

    The pattern goes to DuckDB as a bound parameter, never as SQL text. The only
    text in the SQL besides the schema is the two fixed capture names. Returns
    only the groups that a way matches, or that cannot be proven (see
    `_UNPROVABLE_NAME_SQL`). Returns None when DuckDB rejects the pattern.
    """

    captures = f"[{', '.join(repr(name) for name in group_filter.capture_names)}]"
    ways = {
        # name: (pattern parameter, regexp options)
        "part_sensitive": ("part", ""),
        "full_sensitive": ("full", ""),
        "part_insensitive": ("part", "i"),
        "full_insensitive": ("full", "i"),
    }
    columns = ", ".join(
        f"""CASE WHEN regexp_matches(name, ${param}, '{options}')
            THEN regexp_extract(name, ${param}, {captures}, '{options}') END
            AS {way}"""
        for way, (param, options) in ways.items()
    )
    try:
        rows = con.execute(
            f"""
            WITH named AS (
                SELECT g.id, json_extract_string(g.profile, '$.name') AS name,
                    g.type, a.name AS source_app
                FROM {schema}.groups g
                LEFT JOIN {schema}.applications a
                    ON a.id = json_extract_string(g.source, '$.id')
            ), tested AS (
                SELECT *, {_UNPROVABLE_NAME_SQL} AS unprovable, {columns}
                FROM named WHERE name <> ''
            )
            SELECT id, name, type, source_app, unprovable, {", ".join(ways)}
            FROM tested
            WHERE unprovable OR {" OR ".join(f"{way} IS NOT NULL" for way in ways)}
            """,
            {
                "part": group_filter.pattern,
                # Balanced groups are a rule of the accepted syntax, so the
                # pattern cannot end this wrapper early.
                "full": rf"\A(?:{group_filter.pattern})\z",
                "end_anchored": group_filter.end_anchored,
            },
        ).fetchall()
    except duckdb.InvalidInputException:
        return None
    return [
        GroupNameMatch(
            GroupRef(group_id, name, group_type, source_app),
            tuple((m["role"], m["accountid"]) if m else None for m in found),
            unprovable,
        )
        for group_id, name, group_type, source_app, unprovable, *found in rows
    ]


def aws_group_mapping(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    """Find the groups that group mapping can use for each AWS Account Federation app.

    The Group Filter and App Filter are admin-written text from the application
    settings. They run once for each application, never for each user. Makes
    `aws_group_mapping` (one row for each group that can give a value or a
    reason) and `aws_group_mapping_plans` (the reason when no group can be
    tested, for each application).
    """

    applications: list[tuple[str, str | None]] = con.execute(
        f"""SELECT id, json_extract(settings, '$.app')::VARCHAR
            FROM {schema}.applications WHERE name = ?""",
        [AppName.AWS_ACCOUNT_FEDERATION],
    ).fetchall()
    application_names = frozenset(
        name
        for (name,) in con.execute(f"SELECT name FROM {schema}.applications").fetchall()
    )
    matcher = partial(group_filter_matches, con, schema)
    groups: list[tuple[str, str, str | None, str | None]] = []
    plans: list[tuple[str, str | None]] = []
    for app_id, raw_settings in applications:
        parsed: Any = json.loads(raw_settings) if raw_settings else None
        settings = AwsFederationSettings.from_app_settings(
            parsed if isinstance(parsed, dict) else None
        )
        if not settings.use_group_mapping:
            continue
        plan = plan_group_mapping(settings, application_names, matcher)
        plans.append((app_id, plan.reason))
        groups.extend(
            (app_id, group.group_id, group.value, group.reason) for group in plan.groups
        )
    con.execute(
        f"""CREATE OR REPLACE TABLE {schema}.aws_group_mapping_plans
            (app_id VARCHAR, reason VARCHAR)"""
    )
    con.execute(
        f"""CREATE OR REPLACE TABLE {schema}.aws_group_mapping
            (app_id VARCHAR, group_id VARCHAR, value VARCHAR, reason VARCHAR)"""
    )
    # `executemany` refuses an empty list.
    if plans:
        con.executemany(
            f"INSERT INTO {schema}.aws_group_mapping_plans VALUES (?, ?)", plans
        )
    if groups:
        con.executemany(
            f"INSERT INTO {schema}.aws_group_mapping VALUES (?, ?, ?, ?)", groups
        )


def aws_role_sources(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    """Make `aws_role_sources`: the group data for the Role value of each user.

    One row for each user of an `amazon_aws` application, so the conversion
    reads one row for each user and application. `assigned` holds the groups
    assigned to the application, with their role fields, and `mapped` holds the
    groups from `aws_group_mapping`. Both hold only groups in which the user is
    a member with proof: the collected members equal the member count that Okta
    reports. A group without proof sets `assigned_unproven` or `mapped_unproven`
    for the whole application, because it is unproven for every user.
    """

    aws_group_mapping(con, schema)
    con.execute(
        f"""
        CREATE OR REPLACE TABLE {schema}.aws_role_sources AS
        WITH apps AS (
            SELECT id AS app_id FROM {schema}.applications WHERE name = ?
        ), assigned AS (
            SELECT DISTINCT ga.id AS app_id, ga.group_id,
                ga.assignment_profile::VARCHAR AS profile
            FROM {schema}.group_assigned_apps ga JOIN apps ON apps.app_id = ga.id
        ), mapped AS (
            SELECT m.*, EXISTS (
                SELECT 1 FROM assigned a
                WHERE a.app_id = m.app_id AND a.group_id = m.group_id
            ) AS assigned
            FROM {schema}.aws_group_mapping m
        ), collected AS (
            SELECT DISTINCT id AS user_id, group_id FROM {schema}.group_memberships
        ), reported AS (
            SELECT id AS group_id, count(*) AS copies,
                max(COALESCE(
                    TRY_CAST(json_extract_string(_embedded, '$.stats.usersCount') AS BIGINT),
                    TRY_CAST(json_extract_string(_embedded, '$.stats.users_count') AS BIGINT)
                )) AS reported
            FROM {schema}.groups GROUP BY id
        ), proof AS (
            SELECT r.group_id, r.reported > 0 AS has_members,
                r.copies = 1 AND r.reported IS NOT NULL
                    AND (r.reported = 0 OR COALESCE(c.members, 0) = r.reported)
                    AS proven
            FROM reported r LEFT JOIN (
                SELECT group_id, count(*) AS members FROM collected GROUP BY group_id
            ) c USING (group_id)
        ), user_assigned AS (
            SELECT a.app_id, c.user_id,
                list({{'group_id': a.group_id, 'profile': a.profile}}
                    ORDER BY a.group_id) AS assigned
            FROM assigned a
            JOIN proof p ON p.group_id = a.group_id AND p.proven AND p.has_members
            JOIN collected c ON c.group_id = a.group_id
            GROUP BY a.app_id, c.user_id
        ), user_mapped AS (
            SELECT m.app_id, c.user_id,
                list({{'group_id': m.group_id, 'value': m.value, 'reason': m.reason,
                    'assigned': m.assigned}} ORDER BY m.group_id) AS mapped
            FROM mapped m
            JOIN proof p ON p.group_id = m.group_id AND p.proven AND p.has_members
            JOIN collected c ON c.group_id = m.group_id
            GROUP BY m.app_id, c.user_id
        ), assigned_unproven AS (
            SELECT DISTINCT a.app_id FROM assigned a
            JOIN proof p ON p.group_id = a.group_id WHERE NOT p.proven
        ), mapped_unproven AS (
            SELECT DISTINCT m.app_id FROM mapped m
            JOIN proof p ON p.group_id = m.group_id WHERE NOT p.proven
        )
        SELECT u.app_id, u.user_id, ua.assigned, um.mapped,
            u.app_id IN (SELECT app_id FROM assigned_unproven) AS assigned_unproven,
            u.app_id IN (SELECT app_id FROM mapped_unproven) AS mapped_unproven,
            plans.reason AS mapping_reason
        FROM (
            SELECT DISTINCT au.app_id, au.id AS user_id
            FROM {schema}.application_users au JOIN apps ON apps.app_id = au.app_id
        ) u
        LEFT JOIN user_assigned ua USING (app_id, user_id)
        LEFT JOIN user_mapped um USING (app_id, user_id)
        LEFT JOIN {schema}.aws_group_mapping_plans plans ON plans.app_id = u.app_id
        """,
        [AppName.AWS_ACCOUNT_FEDERATION],
    )
    # Index `user_id` alone: DuckDB scans the whole table for a filter on two
    # indexed columns, and a user has a row for only a few applications.
    con.execute(
        f"CREATE INDEX aws_role_sources_idx ON {schema}.aws_role_sources(user_id)"
    )


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    ensure_users_id_index(con, schema)
    principals_with_admin_roles(con, schema)
    insert_principals_with_admin_roles(con, schema)
    non_admin_users(con, schema)
    non_admin_groups(con, schema)
    non_admin_apps(con, schema)
    try:
        aws_role_sources(con, schema)
    except duckdb.CatalogException:
        # A table is missing, so conversion cannot read the group data and the
        # Role value is incomplete.
        pass
