from datetime import UTC, datetime

from openhound_okta.models import AuthServer, IdentityProvider, Policy, Realm
from openhound_okta.source import policy_types


class StubLookup:
    def org_id(self):
        return "org-1"


def attach_context(asset):
    asset._lookup = StubLookup()
    asset._extras = {"tenant": "example.okta.com"}
    return asset


def test_identity_provider_emits_oktahound_derived_properties():
    idp = attach_context(
        IdentityProvider.model_validate(
            {
                "id": "idp-1",
                "type": "SAML2",
                "name": "Entra SAML",
                "status": "ACTIVE",
                "created": "2026-01-01T00:00:00Z",
                "lastUpdated": "2026-01-02T00:00:00Z",
                "issuerMode": "DYNAMIC",
                "protocol": {
                    "type": "SAML2",
                    "endpoints": {
                        "sso": {
                            "url": "https://login.microsoftonline.com/"
                            "31537af4-6d77-4bb9-a681-d2394888ea26/saml2"
                        }
                    },
                },
                "policy": {
                    "provisioning": {
                        "action": "AUTO",
                        "groups": {"assignments": ["group-1"], "filter": []},
                    }
                },
            }
        )
    )

    properties = idp.as_node.properties

    assert properties.okta_domain == "example.okta.com"
    assert properties.enabled is True
    assert properties.auto_user_provisioning is True
    assert properties.issuer_mode == "DYNAMIC"
    assert properties.governed_group_ids == ["group-1"]
    assert properties.protocol_type == "SAML2"
    assert properties.entra_tenant_id == "31537af4-6d77-4bb9-a681-d2394888ea26"
    assert not hasattr(properties, "status")
    assert not hasattr(properties, "last_updated")


def test_identity_provider_does_not_derive_entra_tenant_id_from_hostname():
    idp = attach_context(
        IdentityProvider.model_validate(
            {
                "id": "idp-1",
                "type": "SAML2",
                "name": "Malformed Entra SAML",
                "status": "ACTIVE",
                "created": "2026-01-01T00:00:00Z",
                "lastUpdated": "2026-01-02T00:00:00Z",
                "protocol": {
                    "type": "SAML2",
                    "endpoints": {
                        "sso": {"url": "https://login.microsoftonline.com/saml2"}
                    },
                },
            }
        )
    )

    assert idp.entra_tenant_id is None


def test_authorization_server_policy_and_realm_emit_native_property_names():
    auth_server = attach_context(
        AuthServer.model_validate(
            {
                "id": "auth-server-1",
                "name": "default",
                "issuer": "https://example.okta.com/oauth2/default",
                "status": "ACTIVE",
                "created": "2026-01-01T00:00:00Z",
            }
        )
    )
    policy = attach_context(
        Policy.model_validate(
            {
                "id": "policy-1",
                "name": "Default Policy",
                "type": "ACCESS_POLICY",
                "created": "2026-01-01T00:00:00Z",
            }
        )
    )
    realm = attach_context(
        Realm.model_validate(
            {
                "id": "realm-1",
                "created": "2026-01-01T00:00:00Z",
                "isDefault": False,
                "profile": {
                    "name": "Partner Realm",
                    "realmType": "PARTNER",
                    "domains": ["example.com"],
                },
            }
        )
    )

    assert auth_server.as_node.properties.okta_domain == "example.okta.com"
    assert policy.as_node.properties.okta_domain == "example.okta.com"
    assert policy.as_node.properties.type == "ACCESS_POLICY"
    assert not hasattr(policy.as_node.properties, "policy_type")
    assert realm.as_node.properties.okta_domain == "example.okta.com"
    assert realm.as_node.properties.type == "PARTNER"
    assert not hasattr(realm.as_node.properties, "realm_type")


def test_policy_parses_native_okta_payload():
    # Shape of a GET /api/v1/policies item as returned by Okta; `conditions` is
    # the native key (an object or null), not `condition`.
    policy = attach_context(
        Policy.model_validate(
            {
                "id": "rstw0o8ijtDUPgM4W697",
                "status": "ACTIVE",
                "name": "Okta Admin Console",
                "priority": 1,
                "system": False,
                "conditions": None,
                "created": "2025-10-02T09:21:35.000Z",
                "lastUpdated": "2025-10-02T09:21:35.000Z",
                "_links": {
                    "self": {"href": "https://example.okta.com/api/v1/policies/x"}
                },
                "_embedded": {"resourceType": "APP"},
                "type": "ACCESS_POLICY",
            }
        )
    )

    assert policy.conditions is None
    assert not hasattr(policy, "condition")
    assert policy.created == datetime(2025, 10, 2, 9, 21, 35, tzinfo=UTC)
    properties = policy.as_node.properties
    assert properties.priority == 1
    assert properties.system is False
    assert properties.created == datetime(2025, 10, 2, 9, 21, 35, tzinfo=UTC)


def test_policy_type_collection_covers_every_documented_policy_type():
    # Every value of the management API's PolicyType enum.
    assert {policy_type["policy_type"] for policy_type in policy_types()} == {
        "OKTA_SIGN_ON",
        "PASSWORD",
        "MFA_ENROLL",
        "IDP_DISCOVERY",
        "ACCESS_POLICY",
        "DEVICE_SIGNAL_COLLECTION",
        "PROFILE_ENROLLMENT",
        "POST_AUTH_SESSION",
        "ENTITY_RISK",
        "SESSION_VIOLATION_DETECTION",
        "CLIENT_UPDATE",
        "IDENTITY_CLAIM_SOURCING",
    }
