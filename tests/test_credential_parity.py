from types import SimpleNamespace

from openhound_okta.models import (
    ApiService,
    ApiToken,
    ApplicationJWKS,
    ApplicationSecrets,
)
from openhound_okta.models.api_token import token_window_timespan
from openhound_okta.source import application_jwk_rows


class StubLookup:
    def org_id(self):
        return "org-1"


def attach_context(asset):
    asset._lookup = StubLookup()
    asset._extras = {"tenant": "example.okta.com"}
    return asset


def test_api_service_and_client_secret_emit_oktahound_domain_property():
    api_service = attach_context(
        ApiService.model_validate(
            {
                "id": "integration-1",
                "type": "my_app_cie",
                "name": "My App Cloud Identity Engine",
                "createdAt": "2026-01-01T00:00:00Z",
                "createdBy": "user-1",
                "grantedScopes": ["okta.users.read"],
            }
        )
    )
    secret = attach_context(
        ApplicationSecrets.model_validate(
            {
                "id": "secret-1",
                "secret_hash": "hash-1",
                "status": "ACTIVE",
                "created": "2026-01-01T00:00:00Z",
                "lastUpdated": "2026-01-02T00:00:00Z",
                "app_id": "app-1",
                "app_name": "App 1",
            }
        )
    )

    assert api_service.as_node.properties.okta_domain == "example.okta.com"
    assert secret.as_node.properties.okta_domain == "example.okta.com"


def test_jwk_node_uses_kid_for_display_and_emits_native_properties():
    jwk = attach_context(
        ApplicationJWKS.model_validate(
            {
                "id": "jwk-1",
                "kid": "kid-1",
                "kty": "RSA",
                "use": "sig",
                "status": "ACTIVE",
                "created": "2026-01-01T00:00:00Z",
                "lastUpdated": "2026-01-02T00:00:00Z",
                "app_id": "app-1",
                "app_name": "App 1",
            }
        )
    )

    properties = jwk.as_node.properties

    assert properties.name == "kid-1"
    assert properties.displayname == "kid-1"
    assert properties.okta_domain == "example.okta.com"
    assert properties.kid == "kid-1"
    assert properties.kty == "RSA"
    assert properties.use == "sig"
    assert properties.created.isoformat() == "2026-01-01T00:00:00+00:00"
    assert properties.last_updated.isoformat() == "2026-01-02T00:00:00+00:00"


def test_api_token_emits_native_properties_and_normalized_token_window():
    token = attach_context(
        ApiToken.model_validate(
            {
                "id": "token-1",
                "name": "My API Token",
                "userId": "user-1",
                "tokenWindow": "P30D",
                "network": {"connection": "ANYWHERE"},
                "clientName": "Okta API",
                "expiresAt": "2026-02-01T00:00:00Z",
                "created": "2026-01-01T00:00:00Z",
                "lastUpdated": "2026-01-02T00:00:00Z",
            }
        )
    )

    properties = token.as_node.properties

    assert properties.okta_domain == "example.okta.com"
    assert properties.network_connection == "ANYWHERE"
    assert properties.token_window == "30.00:00:00"
    assert properties.expires_at.isoformat() == "2026-02-01T00:00:00+00:00"


def test_api_token_allows_missing_nullable_client_fields():
    token = attach_context(
        ApiToken.model_validate(
            {
                "id": "token-1",
                "name": "My API Token",
                "userId": "user-1",
                "created": "2026-01-01T00:00:00Z",
            }
        )
    )

    properties = token.as_node.properties

    assert properties.client_name is None
    assert properties.expires_at is None


def test_token_window_timespan_matches_dotnet_style_duration_strings():
    assert token_window_timespan("P30D") == "30.00:00:00"
    assert token_window_timespan("PT5M") == "00:05:00"
    assert token_window_timespan("PT1H2M3S") == "01:02:03"
    assert token_window_timespan(None) is None


class FakePool:
    def __init__(self):
        self.paths: list[str] = []

    def paginate(self, path: str):
        self.paths.append(path)
        return [
            [
                {
                    "id": "jwk-1",
                    "kid": "kid-1",
                    "kty": "RSA",
                    "use": "sig",
                    "status": "ACTIVE",
                    "created": "2026-01-01T00:00:00Z",
                    "lastUpdated": "2026-01-02T00:00:00Z",
                }
            ]
        ]


def test_application_jwk_rows_use_credentials_endpoint_for_full_jwk_metadata():
    application = SimpleNamespace(
        id="app-1",
        name="App 1",
        settings=SimpleNamespace(
            oauth_client=SimpleNamespace(
                jwks=SimpleNamespace(
                    keys=[
                        SimpleNamespace(
                            model_dump=lambda: {
                                "id": "jwk-1",
                                "kid": "kid-1",
                                "status": "ACTIVE",
                            }
                        )
                    ]
                )
            )
        ),
    )
    pool = FakePool()

    rows = list(application_jwk_rows(application, SimpleNamespace(pool=pool)))

    assert pool.paths == ["/api/v1/apps/app-1/credentials/jwks"]
    assert rows == [
        {
            "app_id": "app-1",
            "app_name": "App 1",
            "id": "jwk-1",
            "kid": "kid-1",
            "kty": "RSA",
            "use": "sig",
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
            "lastUpdated": "2026-01-02T00:00:00Z",
        }
    ]
