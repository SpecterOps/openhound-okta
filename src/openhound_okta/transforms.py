from pathlib import Path

import duckdb

USERS_ID_INDEX_NAME = "users_id_idx"
SQL_TRANSFORMS_PATH = Path(__file__).parent / "sql"
SCHEMA_PLACEHOLDER = "__SCHEMA__"
SQL_TRANSFORMS_FILES = (
    "10_principals_with_admin_roles.sql",
    "20_insert_privileged_users.sql",
    "21_insert_user_role_assignments.sql",
    "22_insert_group_role_assignments.sql",
    "23_insert_client_role_assignments.sql",
    "30_deduplicate_admin_principals.sql",
    "40_non_admin_users.sql",
    "50_non_admin_groups.sql",
    "60_non_admin_apps.sql",
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


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "okta") -> None:
    """Execute preprocessing SQL files in their declared order."""
    for filename in SQL_TRANSFORMS_FILES:
        query = (
            (SQL_TRANSFORMS_PATH / filename)
            .read_text(encoding="utf-8")
            .replace(SCHEMA_PLACEHOLDER, schema)
        )
        con.execute(query)
