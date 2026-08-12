from dataclasses import asdict

import pytest

from openhound.core.models.entries_dataclass import ConditionalEdgePath, EdgePath
from openhound.sources.opengraph.entries import GraphContent

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.models import Application


class StubLookup:
    def org_id(self):
        return "org-1"

    def has_role_assignments(self, principal_id, principal_type):
        assert principal_id == "app-1"
        assert principal_type == "client"
        return False

    def application_oauth_scopes(self, app_id):
        assert app_id == "app-1"
        return ()

    def application_domain_sid(self, app_id):
        assert app_id == "app-1"
        return None


def make_application(
    *,
    name: str,
    sign_on_mode: str,
    app_settings: dict | None = None,
    oauth_client: dict | None = None,
) -> Application:
    settings = {"app": app_settings or {}}
    if oauth_client:
        settings["oauthClient"] = oauth_client

    application = Application.model_validate(
        {
            "id": "app-1",
            "orn": "orn:okta:idp:example:apps:app-1",
            "name": name,
            "label": "Example App",
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
            "signOnMode": sign_on_mode,
            "settings": settings,
        }
    )
    application._lookup = StubLookup()
    application._extras = {"tenant": "example.okta.com"}
    return application


def outbound_edges(application: Application):
    return [
        edge
        for edge in application.edges
        if edge.kind in {ek.OUTBOUND_ORG_SSO, ek.ORG_SWA}
    ]


@pytest.mark.parametrize(
    ("name", "sign_on_mode", "app_settings", "expected_kind", "expected_value"),
    [
        (
            "okta_org2org",
            "SAML_2_0",
            {"idpId": "0oa-target-idp"},
            ek.OUTBOUND_ORG_SSO,
            "0OA-TARGET-IDP",
        ),
        (
            "jamfsoftwareserver",
            "SAML_2_0",
            {"domain": "example.jamfcloud.com"},
            ek.OUTBOUND_ORG_SSO,
            "EXAMPLE.JAMFCLOUD.COM-SSO",
        ),
        (
            "casper",
            "BROWSER_PLUGIN",
            {"domain": "example.jamfcloud.com"},
            ek.ORG_SWA,
            "EXAMPLE.JAMFCLOUD.COM-SSO",
        ),
        (
            "snowflake",
            "SAML_2_0",
            {"subDomain": "cgxovhz-nr46411"},
            ek.OUTBOUND_ORG_SSO,
            "CGXOVHZ-NR46411",
        ),
        (
            "office365",
            "OPENID_CONNECT",
            {"microsoftTenantId": "31537af4-6d77-4bb9-a681-d2394888ea26"},
            ek.OUTBOUND_ORG_SSO,
            "31537AF4-6D77-4BB9-A681-D2394888EA26",
        ),
    ],
)
def test_application_emits_id_based_outbound_trust_edges(
    name, sign_on_mode, app_settings, expected_kind, expected_value
):
    application = make_application(
        name=name,
        sign_on_mode=sign_on_mode,
        app_settings=app_settings,
    )

    edges = outbound_edges(application)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind == expected_kind
    assert isinstance(edge.end, EdgePath)
    assert edge.end.value == expected_value
    assert edge.properties.mode == sign_on_mode
    assert edge.properties.traversable is (expected_kind == ek.OUTBOUND_ORG_SSO)


def test_github_outbound_trust_preserves_oktahound_name_only_matching():
    application = make_application(
        name="githubcloud",
        sign_on_mode="SAML_2_0",
        app_settings={"githubOrg": "example-org"},
    )

    edge = outbound_edges(application)[0]

    assert edge.kind == ek.OUTBOUND_ORG_SSO
    assert isinstance(edge.end, ConditionalEdgePath)
    assert edge.end.kind == nk.GITHUB_ORGANIZATION
    assert [(matcher.key, matcher.value) for matcher in edge.end.property_matchers] == [
        ("name", "EXAMPLE-ORG")
    ]


def test_one_password_outbound_trust_uses_domain_property_matching():
    application = make_application(
        name="1password_business",
        sign_on_mode="SAML_2_0",
        app_settings={"subDomain": "contoso", "regionType": "com"},
    )

    edge = outbound_edges(application)[0]

    assert edge.kind == ek.OUTBOUND_ORG_SSO
    assert isinstance(edge.end, ConditionalEdgePath)
    assert edge.end.kind == nk.ONE_PASSWORD_ACCOUNT
    assert [(matcher.key, matcher.value) for matcher in edge.end.property_matchers] == [
        ("domain", "contoso.1password.com")
    ]


def test_outbound_trust_edges_validate_against_openhound_graph_content():
    github = make_application(
        name="githubcloud",
        sign_on_mode="SAML_2_0",
        app_settings={"githubOrg": "example-org"},
    )
    jamf = make_application(
        name="jamfsoftwareserver",
        sign_on_mode="SAML_2_0",
        app_settings={"domain": "example.jamfcloud.com"},
    )

    payload = {
        "graph": {
            "entity_type": "edge",
            "content": [
                asdict(outbound_edges(github)[0]),
                asdict(outbound_edges(jamf)[0]),
            ],
        }
    }

    graph_content = GraphContent.model_validate(payload)

    assert len(graph_content.graph.content) == 2


@pytest.mark.parametrize(
    ("name", "sign_on_mode", "app_settings", "oauth_client"),
    [
        ("githubcloud", "SAML_2_0", {}, None),
        ("unsupported_app", "SAML_2_0", {"domain": "example.com"}, None),
        ("active_directory", "SAML_2_0", {"namingContext": "example.com"}, None),
        (
            "oidc_client",
            "OPENID_CONNECT",
            {"microsoftTenantId": "tenant-id"},
            {"application_type": "service"},
        ),
        ("githubcloud", "BOOKMARK", {"githubOrg": "example-org"}, None),
    ],
)
def test_application_skips_unsupported_or_unresolvable_outbound_trust_edges(
    name, sign_on_mode, app_settings, oauth_client
):
    application = make_application(
        name=name,
        sign_on_mode=sign_on_mode,
        app_settings=app_settings,
        oauth_client=oauth_client,
    )

    assert outbound_edges(application) == []
