import duckdb


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
        f"SELECT source_id AS id, 'user'   AS principal_type FROM {schema}.user_role_assignments",
        f"SELECT source_id AS id, 'group'  AS principal_type FROM {schema}.group_role_assignments",
        f"SELECT source_id AS id, 'client' AS principal_type FROM {schema}.client_role_assignments",
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
