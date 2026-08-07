from types import SimpleNamespace

import duckdb

from openhound_okta.kinds import edges as ek
from openhound_okta.lookup import OktaLookup
from openhound_okta.models import ApiService, ApiServiceSecrets, ApplicationSecrets
from openhound_okta.source import (
    api_service_secret_rows,
    api_service_secrets,
    api_services,
    application_secrets,
)


class FakePool:
    def __init__(self):
        self.paths: list[str] = []

    def paginate(self, path: str):
        self.paths.append(path)
        return [
            [
                {
                    "id": "secret-1",
                    "secret_hash": "hash-1",
                    "status": "ACTIVE",
                }
            ]
        ]


def make_api_service() -> ApiService:
    return ApiService.model_validate(
        {
            "id": "integration-1",
            "type": "my_app_cie",
            "name": "My App Cloud Identity Engine",
            "createdAt": "2026-01-01T00:00:00Z",
            "createdBy": "user-1",
            "grantedScopes": ["okta.users.read"],
        }
    )


def test_api_service_secret_rows_use_the_integration_credentials_endpoint():
    pool = FakePool()

    rows = list(api_service_secret_rows(make_api_service(), SimpleNamespace(pool=pool)))

    assert pool.paths == [
        "/integrations/api/v1/api-services/integration-1/credentials/secrets"
    ]
    assert rows == [
        {
            "app_id": "integration-1",
            "app_name": "My App Cloud Identity Engine",
            "id": "secret-1",
            "secret_hash": "hash-1",
            "status": "ACTIVE",
        }
    ]


def test_api_service_resources_return_models_for_secret_transformers():
    assert ApiService.dlt_config == {"return_validated_models": True}


def test_api_services_flatten_pages_for_secret_transformers():
    class ApiServicePool:
        def paginate(self, path: str):
            assert path == "/integrations/api/v1/api-services"
            return [
                [
                    {
                        "id": "integration-1",
                        "type": "my_app_cie",
                        "name": "My App Cloud Identity Engine",
                        "createdAt": "2026-01-01T00:00:00Z",
                        "createdBy": "user-1",
                        "grantedScopes": ["okta.users.read"],
                    }
                ]
            ]

    rows = list(api_services(SimpleNamespace(pool=ApiServicePool())))

    assert len(rows) == 1
    assert isinstance(rows[0], ApiService)
    assert rows[0].id == "integration-1"


def test_api_service_secrets_emit_secret_of_edges_to_the_integration():
    secret = ApiServiceSecrets.model_validate(
        {
            "id": "secret-1",
            "secret_hash": "hash-1",
            "status": "ACTIVE",
            "app_id": "integration-1",
            "app_name": "My App Cloud Identity Engine",
        }
    )

    edge = next(secret.edges)

    assert edge.kind == ek.SECRET_OF
    assert edge.start.value == "SECRET-1"
    assert edge.end.value == "INTEGRATION-1"


def test_application_and_api_service_secrets_use_distinct_graph_models():
    assert application_secrets.validator.model is ApplicationSecrets
    assert api_service_secrets.validator.model is ApiServiceSecrets


def test_secret_lookup_includes_application_and_api_service_secret_tables():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.application_secrets (id VARCHAR, app_id VARCHAR)")
    con.execute("CREATE TABLE okta.api_service_secrets (id VARCHAR, app_id VARCHAR)")
    con.execute(
        "INSERT INTO okta.application_secrets VALUES ('app-secret-1', 'app-1')"
    )
    con.execute(
        "INSERT INTO okta.api_service_secrets VALUES "
        "('service-secret-1', 'integration-1')"
    )
    lookup = OktaLookup(con)

    assert lookup.application_secret_ids("app-1") == (("app-secret-1",),)
    assert lookup.application_secret_ids("integration-1") == (
        ("service-secret-1",),
    )
