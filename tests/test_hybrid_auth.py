import pytest

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.models.hybrid_auth import (
    HybridAuthEdgeProperties,
    hybrid_application_edge_kind,
    hybrid_group_target,
    hybrid_user_sign_on_edge_kind,
    hybrid_user_target,
    okta_org2org_domain,
    one_password_domain,
    outbound_trust_target,
)


@pytest.mark.parametrize(
    ("sign_on_mode", "expected_kind"),
    [
        ("SAML_2_0", ek.OUTBOUND_SSO),
        ("SAML_1_1", ek.OUTBOUND_SSO),
        ("WS_FEDERATION", ek.OUTBOUND_SSO),
        ("OPENID_CONNECT", ek.OUTBOUND_SSO),
        ("AUTO_LOGIN", ek.SWA),
        ("BASIC_AUTH", ek.SWA),
        ("BROWSER_PLUGIN", ek.SWA),
        ("BOOKMARK", None),
        (None, None),
    ],
)
def test_hybrid_user_sign_on_edge_kind_matches_oktahound(sign_on_mode, expected_kind):
    assert hybrid_user_sign_on_edge_kind(sign_on_mode) == expected_kind


@pytest.mark.parametrize(
    ("app_name", "sign_on_mode", "is_service", "expected_kind"),
    [
        ("githubcloud", "SAML_2_0", False, ek.OUTBOUND_ORG_SSO),
        ("office365", "OPENID_CONNECT", False, ek.OUTBOUND_ORG_SSO),
        ("casper", "BROWSER_PLUGIN", False, ek.ORG_SWA),
        ("active_directory", "SAML_2_0", False, None),
        ("ldap_interface", "SAML_2_0", False, None),
        ("oidc_client", "OPENID_CONNECT", True, None),
        ("bookmark", "BOOKMARK", False, None),
    ],
)
def test_hybrid_application_edge_kind_matches_oktahound(
    app_name, sign_on_mode, is_service, expected_kind
):
    assert (
        hybrid_application_edge_kind(
            app_name, sign_on_mode, is_service=is_service
        )
        == expected_kind
    )


@pytest.mark.parametrize(
    ("app_name", "settings", "expected_kind", "expected_match_by", "expected_value"),
    [
        (
            "okta_org2org",
            {"idpId": "0oa-target-idp"},
            nk.IDP,
            "id",
            "0oa-target-idp",
        ),
        (
            "jamfsoftwareserver",
            {"domain": "example.jamfcloud.com"},
            nk.JAMF_SSO_INTEGRATION,
            "id",
            "example.jamfcloud.com-SSO",
        ),
        (
            "casper",
            {"domain": "example.jamfcloud.com"},
            nk.JAMF_SSO_INTEGRATION,
            "id",
            "example.jamfcloud.com-SSO",
        ),
        (
            "githubcloud",
            {"githubOrg": "example-org"},
            nk.GITHUB_ORGANIZATION,
            "name",
            "example-org",
        ),
        (
            "snowflake",
            {"subDomain": "cgxovhz-nr46411"},
            nk.SNOWFLAKE_ACCOUNT,
            "id",
            "CGXOVHZ-NR46411",
        ),
        (
            "office365",
            {"microsoftTenantId": "31537af4-6d77-4bb9-a681-d2394888ea26"},
            nk.AZ_TENANT,
            "id",
            "31537af4-6d77-4bb9-a681-d2394888ea26",
        ),
    ],
)
def test_outbound_trust_targets_match_oktahound_id_and_name_rules(
    app_name, settings, expected_kind, expected_match_by, expected_value
):
    target = outbound_trust_target(app_name, settings)

    assert target is not None
    assert target.kind == expected_kind
    assert target.match_by == expected_match_by
    assert target.value == expected_value


def test_one_password_outbound_trust_uses_external_collector_property_name():
    target = outbound_trust_target(
        "1password_business",
        {"subDomain": "contoso", "regionType": "com"},
    )

    assert target is not None
    assert target.kind == nk.ONE_PASSWORD_ACCOUNT
    assert target.match_by == "property"
    assert target.property_matchers == (("domain", "contoso.1password.com"),)


@pytest.mark.parametrize(
    ("app_name", "settings", "target_user_name", "external_id", "expected_kind"),
    [
        ("okta_org2org", {}, "ignored", "00u-target-user", nk.USER),
        (
            "jamfsoftwareserver",
            {"domain": "example.jamfcloud.com"},
            "alice@example.com",
            None,
            nk.JAMF_ACCOUNT,
        ),
        (
            "casper",
            {"domain": "example.jamfcloud.com"},
            "alice@example.com",
            None,
            nk.JAMF_ACCOUNT,
        ),
        (
            "githubcloud",
            {"githubOrg": "example-org"},
            "alice",
            None,
            nk.GITHUB_USER,
        ),
        (
            "1password_business",
            {"subDomain": "contoso", "regionType": "com"},
            "alice@example.com",
            None,
            nk.ONE_PASSWORD_USER,
        ),
        (
            "snowflake",
            {"subDomain": "cgxovhz-nr46411"},
            "alice@example.com",
            None,
            nk.SNOWFLAKE_USER,
        ),
        (
            "office365",
            {"microsoftTenantId": "31537af4-6d77-4bb9-a681-d2394888ea26"},
            "alice@example.com",
            None,
            nk.AZ_USER,
        ),
    ],
)
def test_hybrid_user_targets_cover_oktahound_supported_apps(
    app_name, settings, target_user_name, external_id, expected_kind
):
    target = hybrid_user_target(
        app_name,
        settings,
        target_user_name=target_user_name,
        external_id=external_id,
    )

    assert target is not None
    assert target.kind == expected_kind


def test_hybrid_user_targets_keep_external_schema_match_properties():
    jamf = hybrid_user_target(
        "jamfsoftwareserver",
        {"domain": "example.jamfcloud.com"},
        target_user_name="alice@example.com",
    )
    github = hybrid_user_target(
        "githubcloud",
        {"githubOrg": "example-org"},
        target_user_name="alice",
    )
    office365 = hybrid_user_target(
        "office365",
        {"microsoftTenantId": "tenant-id"},
        target_user_name="alice@example.com",
    )

    assert jamf is not None
    assert jamf.property_matchers == (
        ("email", "alice@example.com"),
        ("domainName", "example.jamfcloud.com"),
    )
    assert github is not None
    assert github.property_matchers == (
        ("login", "alice"),
        ("environment_name", "example-org"),
    )
    assert office365 is not None
    assert office365.property_matchers == (
        ("userprincipalname", "alice@example.com"),
        ("tenantid", "tenant-id"),
    )


@pytest.mark.parametrize(
    ("app_name", "settings", "expected_kind", "expected_matchers"),
    [
        (
            "active_directory",
            {"namingContext": "corp.example.com"},
            nk.AD_GROUP,
            (
                ("samaccountname", "Engineering"),
                ("domain", "corp.example.com"),
            ),
        ),
        (
            "okta_org2org",
            {"baseUrl": "https://target.example.okta.com/"},
            nk.GROUP,
            (
                ("name", "Engineering"),
                ("domainName", "target.example.okta.com"),
            ),
        ),
        (
            "office365",
            {"microsoftTenantId": "tenant-id"},
            nk.AZ_GROUP,
            (
                ("displayname", "Engineering"),
                ("tenantid", "tenant-id"),
            ),
        ),
    ],
)
def test_hybrid_group_targets_match_bloodhound_properties(
    app_name, settings, expected_kind, expected_matchers
):
    target = hybrid_group_target(
        app_name,
        settings,
        group_name="Engineering",
    )

    assert target is not None
    assert target.kind == expected_kind
    assert target.match_by == "property"
    assert target.property_matchers == expected_matchers


def test_snowflake_user_target_uses_uppercase_composite_object_id():
    target = hybrid_user_target(
        "snowflake",
        {"subDomain": "cgxovhz-nr46411"},
        target_user_name="alice@example.com",
    )

    assert target is not None
    assert target.match_by == "id"
    assert target.value == "CGXOVHZ-NR46411.ALICE@EXAMPLE.COM"


def test_missing_or_unsupported_hybrid_targets_are_not_emitted():
    assert outbound_trust_target("githubcloud", {}) is None
    assert outbound_trust_target("unsupported_app", {"domain": "example.com"}) is None
    assert (
        hybrid_user_target(
            "office365",
            {},
            target_user_name="alice@example.com",
        )
        is None
    )
    assert (
        hybrid_user_target(
            "unsupported_app",
            {"domain": "example.com"},
            target_user_name="alice@example.com",
        )
        is None
    )
    assert (
        hybrid_user_target(
            "1password_business",
            {"subDomain": "contoso", "regionType": "com"},
            target_user_name="",
        )
        is None
    )
    assert hybrid_group_target("unsupported_app", {}, group_name="Engineering") is None
    assert hybrid_group_target("okta_org2org", {}, group_name="Engineering") is None


def test_okta_org2org_and_one_password_helpers_match_oktahound():
    assert okta_org2org_domain("https://target.okta.com") == "target.okta.com"
    assert okta_org2org_domain("not-a-url") is None
    assert one_password_domain("contoso", "com") == "contoso.1password.com"
    assert one_password_domain("contoso", None) is None


def test_hybrid_auth_edge_properties_preserve_mode():
    properties = HybridAuthEdgeProperties(traversable=True, mode="SAML_2_0")

    assert properties.traversable is True
    assert properties.mode == "SAML_2_0"


def test_hybrid_swa_edge_definitions_cover_supported_external_targets():
    import openhound_okta.source  # noqa: F401
    from openhound_okta.main import app

    declared_edges = {
        (edge.kind, edge.start, edge.end, edge.traversable) for edge in app.edges
    }

    assert {
        (ek.ORG_SWA, nk.APPLICATION, nk.GITHUB_ORGANIZATION, False),
        (ek.ORG_SWA, nk.APPLICATION, nk.ONE_PASSWORD_ACCOUNT, False),
        (ek.ORG_SWA, nk.APPLICATION, nk.SNOWFLAKE_ACCOUNT, False),
        (ek.ORG_SWA, nk.APPLICATION, nk.AZ_TENANT, False),
        (ek.SWA, nk.USER, nk.GITHUB_USER, False),
        (ek.SWA, nk.USER, nk.SNOWFLAKE_USER, False),
    } <= declared_edges
