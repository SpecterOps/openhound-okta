import duckdb
import pytest

import openhound_okta.transforms as transforms_module
from openhound_okta.transforms import USERS_ID_INDEX_NAME, ensure_users_id_index


class _CountingConnection:
    def __init__(self, connection: duckdb.DuckDBPyConnection):
        self.connection = connection
        self.index_ddl_statements = 0

    def execute(self, query, parameters=None):
        normalized = " ".join(query.split()).lower()
        if normalized.startswith(f"create index {USERS_ID_INDEX_NAME}"):
            self.index_ddl_statements += 1
        if parameters is None:
            self.connection.execute(query)
        else:
            self.connection.execute(query, parameters)
        return self

    def fetchall(self):
        return self.connection.fetchall()


def _create_users_table(
    connection: duckdb.DuckDBPyConnection, schema: str = "okta"
) -> None:
    connection.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
    connection.execute(
        f'CREATE TABLE "{schema}".users (id VARCHAR, status VARCHAR, profile JSON)'
    )


def _index_rows(connection: duckdb.DuckDBPyConnection, schema: str) -> list[tuple]:
    return connection.execute(
        """
        SELECT schema_name, table_name, index_name, is_unique, expressions
        FROM duckdb_indexes()
        WHERE schema_name = ? AND index_name = ?
        """,
        [schema, USERS_ID_INDEX_NAME],
    ).fetchall()


def test_users_id_index_is_non_unique_repeat_safe_and_recreated() -> None:
    raw_connection = duckdb.connect(":memory:")
    connection = _CountingConnection(raw_connection)
    _create_users_table(connection)
    connection.execute(
        """
        INSERT INTO okta.users VALUES
            ('duplicate', 'ACTIVE', '{}'),
            ('duplicate', 'SUSPENDED', '{}')
        """
    )

    assert ensure_users_id_index(connection) is True
    assert _index_rows(connection, "okta") == [
        ("okta", "users", USERS_ID_INDEX_NAME, False, "[id]")
    ]
    assert ensure_users_id_index(connection) is False
    assert len(_index_rows(connection, "okta")) == 1
    assert connection.index_ddl_statements == 1

    connection.execute(
        """
        CREATE OR REPLACE TABLE okta.users (
            id VARCHAR,
            status VARCHAR,
            profile JSON
        )
        """
    )
    assert _index_rows(connection, "okta") == []
    assert ensure_users_id_index(connection) is True
    assert len(_index_rows(connection, "okta")) == 1
    assert connection.index_ddl_statements == 2
    raw_connection.close()


@pytest.mark.parametrize(
    "index_sql",
    (
        f"CREATE INDEX {USERS_ID_INDEX_NAME} ON okta.unrelated(id)",
        f"CREATE UNIQUE INDEX {USERS_ID_INDEX_NAME} ON okta.users(id)",
        f"CREATE INDEX {USERS_ID_INDEX_NAME} ON okta.users(lower(id))",
    ),
)
def test_users_id_index_rejects_incompatible_index_in_target_schema(
    index_sql: str,
) -> None:
    connection = duckdb.connect(":memory:")
    _create_users_table(connection)
    connection.execute("CREATE TABLE okta.unrelated (id VARCHAR)")
    connection.execute(index_sql)

    with pytest.raises(RuntimeError, match="incompatible DuckDB index"):
        ensure_users_id_index(connection)

    assert len(_index_rows(connection, "okta")) == 1
    connection.close()


def test_users_id_index_ignores_same_name_in_another_schema() -> None:
    connection = duckdb.connect(":memory:")
    _create_users_table(connection, "okta")
    _create_users_table(connection, "another_extension")
    connection.execute(
        f"CREATE INDEX {USERS_ID_INDEX_NAME} ON another_extension.users(id)"
    )

    assert ensure_users_id_index(connection, "okta") is True
    assert _index_rows(connection, "okta") == [
        ("okta", "users", USERS_ID_INDEX_NAME, False, "[id]")
    ]
    assert _index_rows(connection, "another_extension") == [
        ("another_extension", "users", USERS_ID_INDEX_NAME, False, "[id]")
    ]
    connection.close()


def test_transforms_creates_users_index_after_derived_tables(monkeypatch) -> None:
    calls = []
    for name in (
        "principals_with_admin_roles",
        "insert_principals_with_admin_roles",
        "non_admin_users",
        "non_admin_groups",
        "non_admin_apps",
        "ensure_users_id_index",
    ):
        monkeypatch.setattr(
            transforms_module,
            name,
            lambda connection, schema, name=name: calls.append(name),
        )

    transforms_module.transforms(object(), "tenant_schema")

    assert calls == [
        "principals_with_admin_roles",
        "insert_principals_with_admin_roles",
        "non_admin_users",
        "non_admin_groups",
        "non_admin_apps",
        "ensure_users_id_index",
    ]
