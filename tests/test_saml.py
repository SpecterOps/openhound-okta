from openhound_okta.kinds import edges as ek
from openhound_okta.models.application import Application
from openhound_okta.models.application_users import ApplicationUser
from openhound_okta.models.idp import IdentityProvider
from openhound_okta.models.idp_user import IDPUser
from openhound_okta.models.saml import (
    SamlClaimMapping,
    SamlFederationProvider,
    SamlServiceProvider,
    saml_acs_rows,
    saml_application_match_values,
    saml_claim_mapping_rows,
    saml_federation_provider_row,
    saml_idp_user_match_values,
    saml_issuer_row,
    saml_service_provider_row,
    saml_sp_acs_rows,
    saml_trusted_issuer_row,
)


def _application(**overrides) -> Application:
    data = {
        "id": "0oa_saml",
        "orn": "orn:okta:idp:00o:apps:custom_saml:0oa_saml",
        "name": "custom_saml",
        "label": "Custom SAML",
        "status": "ACTIVE",
        "created": "2026-01-01T00:00:00.000Z",
        "lastUpdated": "2026-01-01T00:00:00.000Z",
        "signOnMode": "SAML_2_0",
        "features": [],
        "credentials": {"signing": {}},
        "settings": {
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
            },
        },
    }
    data.update(overrides)
    return Application.model_validate(data)


def _identity_provider(**overrides) -> IdentityProvider:
    data = {
        "id": "0oa_idp",
        "type": "SAML2",
        "name": "Example inbound SAML",
        "status": "ACTIVE",
        "created": "2026-01-01T00:00:00.000Z",
        "lastUpdated": "2026-01-01T00:00:00.000Z",
        "protocol": {
            "type": "SAML2",
            "endpoints": {
                "sso": {
                    "url": "https://idp.example.test/saml/sso",
                    "binding": "HTTP-POST",
                    "destination": "https://idp.example.test/saml/sso",
                },
                "acs": {
                    "binding": "HTTP-POST",
                    "type": "INSTANCE",
                },
            },
            "credentials": {
                "trust": {
                    "issuer": "https://idp.example.test/saml/issuer",
                    "audience": "http://www.okta.com/0oa_idp",
                }
            },
        },
        "_links": {
            "acs": {
                "href": "https://example.okta.test/sso/saml2/0oa_idp",
                "type": "application/xml",
            }
        },
    }
    data.update(overrides)
    return IdentityProvider.model_validate(data)


def _application_user(**overrides) -> ApplicationUser:
    data = {
        "id": "00u_saml_user",
        "created": "2026-01-01T00:00:00.000Z",
        "profile": {
            "login": "alice@example.test",
            "email": "alice@example.test",
            "firstName": "Alice",
            "lastName": "Example",
        },
        "credentials": {"userName": "alice.saml@example.test"},
        "status": "ACTIVE",
        "app_id": "0oa_saml",
        "app_features": [],
        "app_name": "custom_saml",
        "app_label": "Custom SAML",
        "app_sign_on_mode": "SAML_2_0",
        "app_user_name_template": "${source.login}",
    }
    data.update(overrides)
    return ApplicationUser.model_validate(data)


def _idp_user(**overrides) -> IDPUser:
    data = {
        "id": "00u_okta_user",
        "externalId": "external-user-id",
        "created": "2026-01-01T00:00:00.000Z",
        "profile": {
            "email": "alice@example.test",
            "firstName": "Alice",
            "lastName": "Example",
            "subjectNameId": "alice",
            "subjectNameQualifier": "example.test",
        },
        "idp_id": "0oa_idp",
        "idp_type": "SAML2",
        "idp_name": "Example inbound SAML",
        "idp_status": "ACTIVE",
        "idp_subject_user_name_template": "idpuser.subjectNameId",
    }
    data.update(overrides)
    return IDPUser.model_validate(data)


def test_saml_provider_is_emitted_when_route_metadata_is_partial():
    app = _application(settings={"app": {}, "signOn": {}})

    row = saml_federation_provider_row(app)

    assert row is not None
    assert row["id"] == "okta:saml:provider:0oa_saml"
    assert row["issuer_id"] is None
    assert row["acs_ids"] == []

    edge_kinds = [edge.kind for edge in SamlFederationProvider.model_validate(row).edges]
    assert edge_kinds == [ek.SAML_IMPLEMENTS]


def test_saml_provider_links_only_to_resolved_route_nodes():
    app = _application()

    provider = saml_federation_provider_row(app)
    issuer = saml_issuer_row(app)
    acs_rows = saml_acs_rows(app)

    assert provider is not None
    assert issuer is not None
    assert provider["issuer_id"] == issuer["id"]
    assert provider["acs_ids"] == [acs_rows[0]["id"]]

    edge_kinds = [edge.kind for edge in SamlFederationProvider.model_validate(provider).edges]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_ISSUES_AS,
        ek.SAML_ISSUES_ASSERTIONS_TO,
    ]


def test_saml_provider_emits_claim_mapping_explanation():
    app = _application(
        credentials={
            "signing": {},
            "userNameTemplate": {"template": "${source.login}"},
        },
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
                "subjectNameIdTemplate": "${source.login}",
                "subjectNameIdFormat": (
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
                ),
                "configuredAttributeStatements": [
                    {"name": "email", "value": "user.email"},
                ],
            },
        },
    )

    provider = saml_federation_provider_row(app)
    rows = saml_claim_mapping_rows(app)

    assert provider is not None
    assert provider["claim_mapping_ids"] == [
        "okta:saml:claim-mapping:0oa_saml:0",
        "okta:saml:claim-mapping:0oa_saml:1",
    ]
    assert rows[0]["claim_name"] == "NameID"
    assert rows[0]["source_property"] == "source.login"
    assert rows[1]["claim_name"] == "email"
    assert rows[1]["expression"] == "user.email"

    edge_kinds = [edge.kind for edge in SamlFederationProvider.model_validate(provider).edges]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_ISSUES_AS,
        ek.SAML_ISSUES_ASSERTIONS_TO,
        ek.SAML_HAS_CLAIM_MAPPING,
        ek.SAML_HAS_CLAIM_MAPPING,
    ]
    assert SamlClaimMapping.model_validate(rows[0]).claim_name == "NameID"


def test_saml_acs_rows_dedup_repeated_acs_url_and_entity():
    app = _application(
        settings={
            "app": {},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
                "ssoAcsUrl": "https://sp.example.test/saml/consume",
                "audience": "https://sp.example.test/saml",
                "acsEndpoints": [
                    {"url": "https://sp.example.test/saml/consume"},
                    {
                        "url": "https://sp.example.test/saml/consume/alternate",
                        "index": 5,
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    },
                ],
            },
        },
    )

    rows = saml_acs_rows(app)

    assert [row["acs_url"] for row in rows] == [
        "https://sp.example.test/saml/consume",
        "https://sp.example.test/saml/consume/alternate",
    ]
    assert [row["id"] for row in rows] == [
        "okta:saml:acs:0oa_saml:0",
        "okta:saml:acs:0oa_saml:5",
    ]


def test_github_emu_oin_route_uses_enterprise_slug_contract():
    app = _application(
        name="githubenterprisemanageduser",
        settings={
            "app": {"enterpriseName": "k-nexus-global"},
            "signOn": {
                "idpIssuer": "http://www.okta.com/exk123",
            },
        },
    )

    rows = saml_acs_rows(app)

    assert rows == [
        {
            "id": "okta:saml:acs:0oa_saml:0",
            "app_id": "0oa_saml",
            "app_name": "githubenterprisemanageduser",
            "app_label": "Custom SAML",
            "source_object_kind": "Okta_Application",
            "acs_url": "https://github.com/enterprises/k-nexus-global/saml/consume",
            "sp_entity_id": "https://github.com/enterprises/k-nexus-global",
            "index": 0,
            "binding": None,
            "is_default": True,
        }
    ]


def test_saml_eligible_for_uses_configured_match_value():
    app_user = _application_user()

    assert saml_application_match_values(app_user) == ["alice.saml@example.test"]

    edges = list(app_user.edges)
    eligible = [edge for edge in edges if edge.kind == ek.SAML_ELIGIBLE_FOR]
    assert len(eligible) == 1
    assert eligible[0].start.value == "00u_saml_user"
    assert eligible[0].end.value == "okta:saml:provider:0oa_saml"
    assert eligible[0].properties.match_values == ["alice.saml@example.test"]
    assert eligible[0].properties.source_property == "source.login"


def test_saml_service_provider_links_only_to_resolved_route_nodes():
    idp = _identity_provider()

    service_provider = saml_service_provider_row(idp)
    issuer = saml_trusted_issuer_row(idp)
    acs_rows = saml_sp_acs_rows(idp)

    assert service_provider is not None
    assert issuer is not None
    assert service_provider["id"] == "okta:saml:service-provider:0oa_idp"
    assert service_provider["issuer_id"] == issuer["id"]
    assert service_provider["acs_ids"] == [acs_rows[0]["id"]]
    assert issuer["entity_id"] == "https://idp.example.test/saml/issuer"
    assert acs_rows == [
        {
            "id": "okta:saml:sp-acs:0oa_idp:0",
            "app_id": "0oa_idp",
            "app_name": "Example inbound SAML",
            "app_label": "Example inbound SAML",
            "source_object_kind": "Okta_IdentityProvider",
            "acs_url": "https://example.okta.test/sso/saml2/0oa_idp",
            "sp_entity_id": "http://www.okta.com/0oa_idp",
            "index": 0,
            "binding": "HTTP-POST",
            "is_default": True,
        }
    ]

    edge_kinds = [
        edge.kind for edge in SamlServiceProvider.model_validate(service_provider).edges
    ]
    assert edge_kinds == [
        ek.SAML_IMPLEMENTS,
        ek.SAML_TRUSTS_ISSUER,
        ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
    ]


def test_saml_service_provider_is_emitted_when_route_metadata_is_partial():
    idp = _identity_provider(
        protocol={
            "type": "SAML2",
            "endpoints": {
                "sso": {
                    "url": "https://idp.example.test/saml/sso",
                    "binding": "HTTP-POST",
                },
                "acs": {"binding": "HTTP-POST", "type": "INSTANCE"},
            },
            "credentials": {"trust": {}},
        },
        _links={},
    )

    row = saml_service_provider_row(idp)

    assert row is not None
    assert row["issuer_id"] is None
    assert row["acs_ids"] == []

    edge_kinds = [edge.kind for edge in SamlServiceProvider.model_validate(row).edges]
    assert edge_kinds == [ek.SAML_IMPLEMENTS]


def test_saml_has_account_uses_inbound_idp_subject_template():
    idp_user = _idp_user(
        idp_subject_user_name_template=(
            "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier"
        )
    )

    assert saml_idp_user_match_values(idp_user) == ["alice@example.test"]

    edges = list(idp_user.edges)
    account_edges = [edge for edge in edges if edge.kind == ek.SAML_HAS_ACCOUNT]
    assert len(account_edges) == 1
    assert account_edges[0].start.value == "okta:saml:service-provider:0oa_idp"
    assert account_edges[0].end.value == "00u_okta_user"
    assert account_edges[0].properties.match_values == ["alice@example.test"]
    assert (
        account_edges[0].properties.source_property
        == "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier"
    )
