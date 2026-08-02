from dataclasses import asdict

import pytest
from openhound.core.models.entries_dataclass import ConditionalEdgePath, EdgePath
from openhound.sources.opengraph.entries import GraphContent

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.models import ApplicationUser


def make_application_user(
    *,
    app_name: str,
    app_sign_on_mode: str | None,
    app_settings: dict | None = None,
    target_user_name: str | None = "alice@example.com",
    external_id: str | None = None,
    sync_state: str = "SYNCHRONIZED",
) -> ApplicationUser:
    credentials = (
        {"userName": target_user_name} if target_user_name is not None else None
    )
    return ApplicationUser.model_validate(
        {
            "id": "user-1",
            "created": "2026-01-01T00:00:00Z",
            "profile": {},
            "status": "ACTIVE",
            "app_id": "app-1",
            "app_name": app_name,
            "app_label": "Example App",
            "app_settings": app_settings or {},
            "app_sign_on_mode": app_sign_on_mode,
            "credentials": credentials,
            "externalId": external_id,
            "syncState": sync_state,
        }
    )


def hybrid_sign_on_edges(application_user: ApplicationUser):
    return [
        edge
        for edge in application_user.edges
        if edge.kind in {ek.OUTBOUND_SSO, ek.SWA}
    ]


@pytest.mark.parametrize(
    (
        "app_name",
        "sign_on_mode",
        "app_settings",
        "target_user_name",
        "external_id",
        "expected_kind",
        "expected_value",
    ),
    [
        (
            "okta_org2org",
            "SAML_2_0",
            {},
            "ignored",
            "00u-target-user",
            ek.OUTBOUND_SSO,
            "00u-target-user",
        ),
        (
            "snowflake",
            "SAML_2_0",
            {"subDomain": "cgxovhz-nr46411"},
            "alice@example.com",
            None,
            ek.OUTBOUND_SSO,
            "CGXOVHZ-NR46411.ALICE@EXAMPLE.COM",
        ),
    ],
)
def test_application_user_emits_id_based_hybrid_sign_on_edges(
    app_name,
    sign_on_mode,
    app_settings,
    target_user_name,
    external_id,
    expected_kind,
    expected_value,
):
    application_user = make_application_user(
        app_name=app_name,
        app_sign_on_mode=sign_on_mode,
        app_settings=app_settings,
        target_user_name=target_user_name,
        external_id=external_id,
    )

    edges = hybrid_sign_on_edges(application_user)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind == expected_kind
    assert isinstance(edge.end, EdgePath)
    assert edge.end.value == expected_value
    assert edge.properties.mode == sign_on_mode
    assert edge.properties.traversable is True


@pytest.mark.parametrize(
    (
        "app_name",
        "sign_on_mode",
        "app_settings",
        "target_user_name",
        "expected_kind",
        "expected_node_kind",
        "expected_matchers",
    ),
    [
        (
            "jamfsoftwareserver",
            "SAML_2_0",
            {"domain": "example.jamfcloud.com"},
            "alice@example.com",
            ek.OUTBOUND_SSO,
            nk.JAMF_ACCOUNT,
            [("email", "alice@example.com"), ("domainName", "example.jamfcloud.com")],
        ),
        (
            "casper",
            "BROWSER_PLUGIN",
            {"domain": "example.jamfcloud.com"},
            "alice@example.com",
            ek.SWA,
            nk.JAMF_ACCOUNT,
            [("email", "alice@example.com"), ("domainName", "example.jamfcloud.com")],
        ),
        (
            "githubcloud",
            "SAML_2_0",
            {"githubOrg": "example-org"},
            "alice",
            ek.OUTBOUND_SSO,
            nk.GITHUB_USER,
            [("login", "alice"), ("environment_name", "example-org")],
        ),
        (
            "1password_business",
            "BROWSER_PLUGIN",
            {"subDomain": "contoso", "regionType": "com"},
            "alice@example.com",
            ek.SWA,
            nk.ONE_PASSWORD_USER,
            [("email", "alice@example.com"), ("account_name", "contoso.1password.com")],
        ),
        (
            "office365",
            "OPENID_CONNECT",
            {"microsoftTenantId": "tenant-id"},
            "alice@example.com",
            ek.OUTBOUND_SSO,
            nk.AZ_USER,
            [("userprincipalname", "alice@example.com"), ("tenantid", "TENANT-ID")],
        ),
    ],
)
def test_application_user_emits_property_matched_hybrid_sign_on_edges(
    app_name,
    sign_on_mode,
    app_settings,
    target_user_name,
    expected_kind,
    expected_node_kind,
    expected_matchers,
):
    application_user = make_application_user(
        app_name=app_name,
        app_sign_on_mode=sign_on_mode,
        app_settings=app_settings,
        target_user_name=target_user_name,
    )

    edge = hybrid_sign_on_edges(application_user)[0]

    assert edge.kind == expected_kind
    assert isinstance(edge.end, ConditionalEdgePath)
    assert edge.end.kind == expected_node_kind
    assert [(matcher.key, matcher.value) for matcher in edge.end.property_matchers] == (
        expected_matchers
    )
    assert edge.properties.mode == sign_on_mode
    assert edge.properties.traversable is (expected_kind == ek.OUTBOUND_SSO)


def test_hybrid_sign_on_edges_do_not_depend_on_sync_state():
    application_user = make_application_user(
        app_name="githubcloud",
        app_sign_on_mode="SAML_2_0",
        app_settings={"githubOrg": "example-org"},
        target_user_name="alice",
        sync_state="DISABLED",
    )

    edges = hybrid_sign_on_edges(application_user)

    assert len(edges) == 1
    assert edges[0].kind == ek.OUTBOUND_SSO


@pytest.mark.parametrize(
    ("app_name", "sign_on_mode", "app_settings", "target_user_name", "external_id"),
    [
        ("unsupported_app", "SAML_2_0", {}, "alice@example.com", None),
        ("githubcloud", "BOOKMARK", {"githubOrg": "example-org"}, "alice", None),
        ("githubcloud", "SAML_2_0", {}, "alice", None),
        ("githubcloud", "SAML_2_0", {"githubOrg": "example-org"}, None, None),
        ("okta_org2org", "SAML_2_0", {}, None, None),
    ],
)
def test_application_user_skips_unresolvable_hybrid_sign_on_edges(
    app_name, sign_on_mode, app_settings, target_user_name, external_id
):
    application_user = make_application_user(
        app_name=app_name,
        app_sign_on_mode=sign_on_mode,
        app_settings=app_settings,
        target_user_name=target_user_name,
        external_id=external_id,
    )

    assert hybrid_sign_on_edges(application_user) == []


def test_hybrid_sign_on_edges_validate_against_openhound_graph_content():
    github = make_application_user(
        app_name="githubcloud",
        app_sign_on_mode="SAML_2_0",
        app_settings={"githubOrg": "example-org"},
        target_user_name="alice",
    )
    org2org = make_application_user(
        app_name="okta_org2org",
        app_sign_on_mode="SAML_2_0",
        target_user_name="ignored",
        external_id="00u-target-user",
    )

    payload = {
        "graph": {
            "entity_type": "edge",
            "content": [
                asdict(hybrid_sign_on_edges(github)[0]),
                asdict(hybrid_sign_on_edges(org2org)[0]),
            ],
        }
    }

    graph_content = GraphContent.model_validate(payload)

    assert len(graph_content.graph.content) == 2
