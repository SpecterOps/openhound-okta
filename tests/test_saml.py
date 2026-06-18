from openhound_okta.kinds import edges as ek
from openhound_okta.models.application import Application
from openhound_okta.models.saml import (
    SamlFederationProvider,
    saml_acs_rows,
    saml_federation_provider_row,
    saml_issuer_row,
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
            "acs_url": "https://github.com/enterprises/k-nexus-global/saml/consume",
            "sp_entity_id": "https://github.com/enterprises/k-nexus-global",
            "index": 0,
            "binding": None,
            "is_default": True,
        }
    ]
