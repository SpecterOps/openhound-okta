import duckdb

from openhound_okta.lookup import OktaLookup
from openhound_okta.models import Application
from openhound_okta.models.application import _snake_case_property_name


class StubLookup:
    def __init__(self, *, has_role_assignments: bool = False):
        self._has_role_assignments = has_role_assignments

    def org_id(self):
        return "org-1"

    def has_role_assignments(self, principal_id, principal_type):
        assert principal_id == "app-1"
        assert principal_type == "client"
        return self._has_role_assignments

    def application_oauth_scopes(self, app_id):
        assert app_id == "app-1"
        return ()

    def application_domain_sid(self, app_id):
        assert app_id == "app-1"
        return None


def make_application(
    *,
    name: str = "githubcloud",
    label: str = "GitHub Enterprise Cloud",
    has_role_assignments: bool = False,
    **overrides,
):
    application = Application.model_validate(
        {
            "id": "app-1",
            "orn": "orn:okta:idp:example:apps:app-1",
            "name": name,
            "label": label,
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
            **overrides,
        }
    )
    application._lookup = StubLookup(has_role_assignments=has_role_assignments)
    application._extras = {"tenant": "example.okta.com"}
    return application


def test_application_node_uses_label_for_name_and_preserves_raw_app_type():
    application = make_application()

    properties = application.as_node.properties

    assert properties.name == "GitHub Enterprise Cloud"
    assert properties.displayname == "GitHub Enterprise Cloud"
    assert properties.app_type == "githubcloud"
    assert properties.okta_domain == "example.okta.com"
    assert properties.label == "GitHub Enterprise Cloud"


def test_application_node_falls_back_to_raw_app_type_when_label_is_empty():
    application = make_application(name="active_directory", label="")

    properties = application.as_node.properties

    assert properties.name == "active_directory"
    assert properties.displayname == "active_directory"
    assert properties.app_type == "active_directory"


def test_application_node_emits_core_oktahound_equivalent_properties():
    application = make_application(
        name="oidc_client",
        label="Slack Workspace",
        has_role_assignments=True,
        features=["SCIM_PROVISIONING", "PROFILE_MASTERING"],
        signOnMode="OPENID_CONNECT",
        credentials={"userNameTemplate": {"template": "${source.login}"}},
        settings={
            "oauthClient": {
                "application_type": "web",
                "grant_types": ["authorization_code"],
                "redirect_uris": ["https://example.okta.com/callback"],
            }
        },
    )

    properties = application.as_node.properties

    assert properties.has_role_assignments is True
    assert properties.features == ["SCIM_PROVISIONING", "PROFILE_MASTERING"]
    assert properties.client_type == "web"
    assert properties.grant_types == ["authorization_code"]
    assert properties.user_name_mapping == "${source.login}"
    assert properties.url == "https://example.okta.com/callback"


def test_application_node_uses_sign_on_mode_specific_url_sources():
    saml_application = make_application(
        signOnMode="SAML_2_0",
        settings={"signOn": {"ssoAcsUrl": "https://example.okta.com/saml/acs"}},
    )
    bookmark_application = make_application(
        name="bookmark",
        signOnMode="BOOKMARK",
        settings={"app": {"url": "https://example.okta.com/bookmark"}},
    )

    assert saml_application.as_node.properties.url == "https://example.okta.com/saml/acs"
    assert (
        bookmark_application.as_node.properties.url
        == "https://example.okta.com/bookmark"
    )


def test_application_node_emits_primitive_app_settings_in_snake_case():
    application = make_application(
        signOnMode="SAML_2_0",
        settings={
            "app": {
                "githubOrg": "example-org",
                "filterGroupsByOU": True,
                "subDomain": "example",
                "domains": ["example.com", "example.org"],
                "usernameField": "email",
                "emptyList": [],
                "occSettings": {"nested": "ignored"},
                "url": "https://example.okta.com/app",
            }
        }
    )

    properties = application.as_node.properties

    assert properties.github_org == "example-org"
    assert properties.filter_groups_by_ou is True
    assert properties.sub_domain == "example"
    assert properties.domains == ["example.com", "example.org"]
    assert properties.username_field == "email"
    assert properties.url == "https://example.okta.com/app"
    assert not hasattr(properties, "occ_settings")


def test_application_node_does_not_emit_credential_bearing_app_settings():
    application = make_application(
        signOnMode="SAML_2_0",
        settings={
            "app": {
                "accessKey": "access-key-value",
                "password": "password-value",
                "secretKey": "secret-key-value",
                "secretKeyEnc": "encrypted-secret-key-value",
                "passwordField": "password",
            }
        },
    )

    properties = application.as_node.properties

    assert properties.access_key is None
    assert properties.password is None
    assert properties.secret_key is None
    assert properties.secret_key_enc is None
    assert properties.password_field == "password"


def test_application_node_limits_active_directory_settings_to_oktahound_fields():
    application = make_application(
        name="active_directory",
        settings={
            "app": {
                "namingContext": "corp.example.com",
                "filterGroupsByOU": False,
                "jitGroupsAcrossDomains": True,
            }
        },
    )

    properties = application.as_node.properties

    assert properties.naming_context == "corp.example.com"
    assert properties.filter_groups_by_ou is False
    assert properties.jit_groups_across_domains is None


def test_application_node_emits_oauth_scopes_and_ad_domain_sid_from_lookup():
    class LookupWithApplicationMetadata(StubLookup):
        def application_oauth_scopes(self, app_id):
            assert app_id == "app-1"
            return ("okta.users.read", "okta.groups.read")

        def application_domain_sid(self, app_id):
            assert app_id == "app-1"
            return "S-1-5-21-111-222-333"

    application = make_application(name="active_directory")
    application._lookup = LookupWithApplicationMetadata()

    properties = application.as_node.properties

    assert properties.oauth_scopes == ["okta.users.read", "okta.groups.read"]
    assert properties.domain_sid == "S-1-5-21-111-222-333"


def test_application_property_name_conversion_handles_okta_acronyms():
    assert _snake_case_property_name("githubOrg") == "github_org"
    assert _snake_case_property_name("filterGroupsByOU") == "filter_groups_by_ou"
    assert _snake_case_property_name("loginURL") == "login_url"
    assert _snake_case_property_name("redirectURI") == "redirect_uri"
    assert _snake_case_property_name("accountID") == "account_id"


def test_application_lookup_derives_scopes_and_domain_sid():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.application_grants (app_id VARCHAR, scope_id VARCHAR)")
    con.execute(
        "INSERT INTO okta.application_grants VALUES "
        "('app-1', 'okta.users.read'), ('app-1', 'okta.groups.read'), "
        "('app-1', 'okta.users.read'), ('app-1', ''), ('app-1', '   ')"
    )
    con.execute(
        "CREATE TABLE okta.application_users "
        "(app_id VARCHAR, sync_state VARCHAR, profile JSON)"
    )
    con.execute(
        "INSERT INTO okta.application_users VALUES "
        "('app-1', 'SYNCHRONIZED', '{\"objectSid\":\"S-1-5-21-111-222-333-1001\"}')"
    )

    lookup = OktaLookup(con)

    assert lookup.application_oauth_scopes("app-1") == (
        "okta.users.read",
        "okta.groups.read",
        "okta.users.read",
    )
    assert lookup.application_domain_sid("app-1") == "S-1-5-21-111-222-333"
