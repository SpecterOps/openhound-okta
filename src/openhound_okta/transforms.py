import logging
from typing import Final

import duckdb

logger = logging.getLogger(__name__)

DEFAULT_SCHEMA: Final[str] = "okta"
"""DuckDB schema the collection phase loads the Okta tables into."""

USERS_ID_INDEX_NAME: Final[str] = "users_id_idx"
"""Name of the non-unique users(id) index created by ensure_users_id_index."""


def ensure_users_id_index(
    con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA
) -> bool:
    """Create the non-unique users(id) lookup index when it is absent.

    The convert phase issues many point lookups by user ID, so the index is
    created once before the other transforms run. An existing index with the
    expected definition is left untouched.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Returns:
        True when the index was created, False when it already existed.

    Raises:
        RuntimeError: An index with the reserved name exists but is defined on
            another table or column, or is unique.
        duckdb.Error: The users table is absent or the statement fails.
    """

    rows: list[tuple[str, str, str, bool, str]] = con.execute(
        """
        SELECT schema_name, table_name, index_name, is_unique, expressions
        FROM duckdb_indexes()
        WHERE schema_name = ? AND index_name = ?
        ORDER BY schema_name, table_name
        """,
        [schema, USERS_ID_INDEX_NAME],
    ).fetchall()
    if rows:
        expected: tuple[str, str, str, bool, str] = (
            schema,
            "users",
            USERS_ID_INDEX_NAME,
            False,
            "[id]",
        )
        if rows != [expected]:
            raise RuntimeError(
                f"incompatible DuckDB index named {USERS_ID_INDEX_NAME!r}: {rows!r}"
            )
        return False

    quoted_schema: str = schema.replace('"', '""')
    con.execute(f'CREATE INDEX {USERS_ID_INDEX_NAME} ON "{quoted_schema}".users(id)')
    return True


def principals_with_admin_roles(
    con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA
) -> None:
    """Create the empty principals_with_admin_roles staging table.

    The table holds one row per principal that holds an admin role, with
    principal_type set to user, group, or client. It is filled by
    insert_principals_with_admin_roles and consumed by the non_admin_*
    transforms. Any existing table of that name is replaced.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        duckdb.Error: The schema is absent or the statement fails.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.principals_with_admin_roles (
            id VARCHAR,
            principal_type VARCHAR
        )
    """)


def insert_principals_with_admin_roles(
    con: duckdb.DuckDBPyConnection,
    schema: str = DEFAULT_SCHEMA,
) -> None:
    """Fill principals_with_admin_roles from every collected admin source.

    Okta lets only super admins manage users or groups that hold admin
    privileges, whether a user holds the role directly or through an admin
    group, so both kinds of user must be excluded from the targets of
    management edges. The user sources overlap on purpose:

    * privileged_users is Okta's own inventory (GET /api/v1/iam/assignees/
      users). It lists direct assignees and, as observed, members of admin
      groups, but Okta does not document the latter and the listing is a
      single resource that ends on the first failed page.
    * user_role_assignments is derived from privileged_users, so it adds no
      new users; it is kept so the exclusion does not depend on the inventory
      model alone.
    * group_memberships flagged group_has_admin_privilege resolves admin
      group members from the membership data itself, so an inherited admin is
      excluded even when the inventory omits or truncates them.
    * users joined through group_memberships to active
      group_role_assignments resolves the same members from the collected
      role assignments instead of Okta's hasAdminPrivilege group stat, so the
      exclusion also survives a wrong or missing flag.
    * resource_set_role_assignments lists the assignees bound to custom
      roles through resource sets (GET /api/v1/iam/resource-sets/{id}/
      bindings/{roleId}/members), an endpoint family the other sources never
      touch. Assignees are classified by joining to the users, groups, and
      applications tables, and members of bound groups are resolved through
      group_memberships. API service integrations can also be bound but are
      not classified, since non_admin_apps only covers applications.

    Groups and client applications come from their own active role
    assignment rows and from resource set bindings; neither can inherit a
    role. A source whose table is absent because its resource yielded no rows
    is skipped; the inventory logs a warning when skipped, since every org
    has at least one admin. The table is deduplicated once all sources are
    inserted.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        duckdb.Error: The staging table is absent (principals_with_admin_roles
            must run first) or a statement fails for a reason other than a
            missing source table.
    """
    # (source name, SELECT producing id and principal_type)
    principals: list[tuple[str, str]] = [
        (
            "privileged user inventory",
            f"""SELECT DISTINCT id, 'user' AS principal_type
            FROM {schema}.privileged_users""",
        ),
        (
            "direct user role assignments",
            f"""SELECT source_id AS id, 'user' AS principal_type
            FROM {schema}.user_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'USER'""",
        ),
        (
            "members of groups flagged with admin privilege",
            f"""SELECT DISTINCT id, 'user' AS principal_type
            FROM {schema}.group_memberships
            WHERE group_has_admin_privilege""",
        ),
        (
            "members of groups with role assignments",
            f"""SELECT DISTINCT u.id, 'user' AS principal_type
            FROM {schema}.users u
            JOIN {schema}.group_memberships m ON m.id = u.id
            JOIN {schema}.group_role_assignments g ON g.source_id = m.group_id
            WHERE g.status = 'ACTIVE' AND g.assignment_type = 'GROUP'""",
        ),
        (
            "group role assignments",
            f"""SELECT source_id AS id, 'group' AS principal_type
            FROM {schema}.group_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'GROUP'""",
        ),
        (
            "client role assignments",
            f"""SELECT source_id AS id, 'client' AS principal_type
            FROM {schema}.client_role_assignments
            WHERE status = 'ACTIVE' AND assignment_type = 'CLIENT'""",
        ),
        (
            "users bound to resource set roles",
            f"""SELECT DISTINCT u.id, 'user' AS principal_type
            FROM {schema}.users u
            JOIN {schema}.resource_set_role_assignments r ON r.assignee_id = u.id""",
        ),
        (
            "members of groups bound to resource set roles",
            f"""SELECT DISTINCT u.id, 'user' AS principal_type
            FROM {schema}.users u
            JOIN {schema}.group_memberships m ON m.id = u.id
            JOIN {schema}.resource_set_role_assignments r
              ON r.assignee_id = m.group_id""",
        ),
        (
            "groups bound to resource set roles",
            f"""SELECT DISTINCT g.id, 'group' AS principal_type
            FROM {schema}.groups g
            JOIN {schema}.resource_set_role_assignments r ON r.assignee_id = g.id""",
        ),
        (
            "applications bound to resource set roles",
            f"""SELECT DISTINCT a.id, 'client' AS principal_type
            FROM {schema}.applications a
            JOIN {schema}.resource_set_role_assignments r ON r.assignee_id = a.id""",
        ),
    ]
    for source_name, principal in principals:
        try:
            con.execute(f"""
                INSERT INTO {schema}.principals_with_admin_roles
                {principal}
                """)
        except duckdb.CatalogException as e:
            # A source table is absent when its resource yielded no rows,
            # e.g. the request was denied or the listing ended on a failed
            # page. Principals only this source knows about then stay valid
            # targets of management edges, which produces false positives.
            # Every org has at least one admin, so the inventory is unexpected
            # to be unavailable; the other sources may legitimately be empty.
            # The exception names the missing table.
            if source_name == "privileged user inventory":
                logger.warning(
                    "The privileged user inventory is unavailable, so users "
                    "with direct role assignments are not excluded from "
                    "management edge targets: %s",
                    e,
                )

        except Exception as e:
            raise e

    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.principals_with_admin_roles AS
        SELECT DISTINCT id, principal_type
        FROM {schema}.principals_with_admin_roles
    """)


def non_admin_users(
    con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA
) -> None:
    """Create non_admin_users: users holding no admin role.

    These are the only users that admins below super admin can manage, so
    the convert phase intersects them with the scope of every user-targeted
    management edge. Any existing table of that name is replaced.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        duckdb.Error: The users or principals_with_admin_roles table is
            absent or the statement fails.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_users AS
        SELECT id FROM {schema}.users
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'user'
        )
    """)


def non_admin_groups(
    con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA
) -> None:
    """Create non_admin_groups: groups holding no admin role.

    These are the only groups that admins below super admin can manage, so
    the convert phase intersects them with the scope of every group-targeted
    management edge. Any existing table of that name is replaced.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        duckdb.Error: The groups or principals_with_admin_roles table is
            absent or the statement fails.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_groups AS
        SELECT id FROM {schema}.groups
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'group'
        )
    """)


def non_admin_apps(
    con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA
) -> None:
    """Create non_admin_apps: applications holding no admin role.

    Client applications with role assignments cannot be managed by app
    admins, so the convert phase intersects this table with the scope of
    every application-targeted management edge. Any existing table of that
    name is replaced.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        duckdb.Error: The applications or principals_with_admin_roles table
            is absent or the statement fails.
    """
    con.execute(f"""
        CREATE OR REPLACE TABLE {schema}.non_admin_apps AS
        SELECT id FROM {schema}.applications
        WHERE id NOT IN (
            SELECT id FROM {schema}.principals_with_admin_roles
            WHERE principal_type = 'client'
        )
    """)


def transforms(con: duckdb.DuckDBPyConnection, schema: str = DEFAULT_SCHEMA) -> None:
    """Run every preprocessing transform in dependency order.

    Called once by the preproc phase after collection has loaded the raw
    tables. The order matters: the admin-principal staging table must exist
    before it is filled, and the non_admin_* tables read from it.

    Args:
        con: DuckDB connection to the collection database.
        schema: Schema holding the collected Okta tables.

    Raises:
        RuntimeError: See ensure_users_id_index.
        duckdb.Error: A required collected table is absent or a statement
            fails; see the individual transforms.
    """
    ensure_users_id_index(con, schema)
    principals_with_admin_roles(con, schema)
    insert_principals_with_admin_roles(con, schema)
    non_admin_users(con, schema)
    non_admin_groups(con, schema)
    non_admin_apps(con, schema)
