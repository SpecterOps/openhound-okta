import duckdb


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


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    principals_with_admin_roles(con, schema)
    insert_principals_with_admin_roles(con, schema)
    non_admin_users(con, schema)
    non_admin_groups(con, schema)
    non_admin_apps(con, schema)
    ensure_users_id_index(con, schema)
