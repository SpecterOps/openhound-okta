import re
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgePath,
    EdgeProperties,
)
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.hybrid_auth import (
    HybridAuthEdgeProperties,
    hybrid_application_edge_kind,
    hybrid_target_edge_path,
    outbound_trust_target,
)


@dataclass
class ApplicationProperties(OktaNodeProperties):
    """Properties for the Okta_ApplicationNode node.

    Attributes:
        label: Human-readable application label.
        status: Okta application lifecycle status.
        created: Timestamp when the application was created.
        last_updated: Timestamp when the application was last updated.
        sign_on_mode: Authentication mode configured for the application.
        orn: Okta Resource Name for the application.
        idp_id: Native inbound identity-provider ID referenced by the application.
    """

    app_type: str
    okta_domain: str
    label: str
    status: str
    created: datetime
    has_role_assignments: bool = False
    features: list[str] | None = None
    last_updated: datetime | None = None
    sign_on_mode: str | None = None
    client_type: str | None = None
    grant_types: list[str] | None = None
    user_name_mapping: str | None = None
    url: str | None = None
    oauth_scopes: list[str] | None = None
    domain_sid: str | None = None
    access_key: str | None = None
    account_id: str | None = None
    acs_url: str | None = None
    activation_email: str | None = None
    afw_id: str | None = None
    afw_only: bool | None = None
    app_filter: str | None = None
    aud_restriction: str | None = None
    aws_environment_type: str | None = None
    base_url: str | None = None
    button_field: str | None = None
    checkbox: str | None = None
    datacenter_location: str | None = None
    domain: str | None = None
    domain_name: str | None = None
    domains: list[str | bool | int] | None = None
    entity_id: str | None = None
    filter_groups_by_ou: bool | None = None
    github_org: str | None = None
    group_filter: str | None = None
    identity_provider_arn: str | None = None
    idp_id: str | None = None
    initiate_login_uri: str | None = None
    jit_groups_across_domains: bool | None = None
    join_all_roles: bool | None = None
    login: str | None = None
    login_url: str | None = None
    login_url_regex: str | None = None
    microsoft_app_id: str | None = None
    microsoft_discovery_endpoint: str | None = None
    microsoft_tenant_id: str | None = None
    msft_tenant: str | None = None
    naming_context: str | None = None
    office365_flexible_provisioning_mode: str | None = None
    office365_provisioning_type: str | None = None
    override_acs_url: str | None = None
    password: str | None = None
    password_field: str | None = None
    redirect_uri: str | None = None
    redirect_url: str | None = None
    region_type: str | None = None
    request_integration: bool | None = None
    require_admin_consent: bool | None = None
    role_value_pattern: str | None = None
    rp_id: str | None = None
    scan_rate: str | None = None
    search_org_unit: str | None = None
    secret_key: str | None = None
    secret_key_enc: str | None = None
    service_domain: str | None = None
    session_duration: int | None = None
    site_url: str | None = None
    sub_domain: str | None = None
    tenant_type: str | None = None
    use_group_mapping: bool | None = None
    username_field: str | None = None
    web_sso_allowed_client: str | None = None
    windows_transport_enabled: bool | None = None
    ws_fed_configure_type: str | None = None
    orn: str | None = None


APP_SETTING_PROPERTY_NAMES = {
    "access_key",
    "account_id",
    "acs_url",
    "activation_email",
    "afw_id",
    "afw_only",
    "app_filter",
    "aud_restriction",
    "aws_environment_type",
    "base_url",
    "button_field",
    "checkbox",
    "datacenter_location",
    "domain",
    "domain_name",
    "domains",
    "entity_id",
    "filter_groups_by_ou",
    "github_org",
    "group_filter",
    "identity_provider_arn",
    "idp_id",
    "initiate_login_uri",
    "jit_groups_across_domains",
    "join_all_roles",
    "login",
    "login_url",
    "login_url_regex",
    "microsoft_app_id",
    "microsoft_discovery_endpoint",
    "microsoft_tenant_id",
    "msft_tenant",
    "naming_context",
    "office365_flexible_provisioning_mode",
    "office365_provisioning_type",
    "override_acs_url",
    "password",
    "password_field",
    "redirect_uri",
    "redirect_url",
    "region_type",
    "request_integration",
    "require_admin_consent",
    "role_value_pattern",
    "rp_id",
    "scan_rate",
    "search_org_unit",
    "secret_key",
    "secret_key_enc",
    "service_domain",
    "session_duration",
    "site_url",
    "sub_domain",
    "tenant_type",
    "use_group_mapping",
    "url",
    "username_field",
    "web_sso_allowed_client",
    "windows_transport_enabled",
    "ws_fed_configure_type",
}


def _snake_case_property_name(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("-", "_").lower()


def _is_primitive_app_setting(value) -> bool:
    return isinstance(value, (str, bool, int))


def _is_homogeneous_primitive_list(value) -> bool:
    if not isinstance(value, list):
        return False
    if not value:
        return False

    expected_type = type(value[0])
    return all(
        _is_primitive_app_setting(item) and type(item) is expected_type
        for item in value
    )


class JWK(BaseModel):
    id: str
    kid: str | None = None
    alf: str | None = None
    kty: str | None = None
    use: str | None = None
    n: str | None = None
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime | None = None


class OauthKeys(BaseModel):
    keys: list[JWK] = Field(default_factory=list)


class OauthClientSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_uri: str | None = None
    response_types: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)
    application_type: str | None = None
    issuer_mode: str | None = None
    consent_method: str | None = None
    jwks: OauthKeys | None = None
    redirect_uris: list[str] = Field(default_factory=list, alias="redirectUris")
    initiate_login_uri: str | None = Field(default=None, alias="initiateLoginUri")


class SamlAcsEndpoint(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    url: str | None = None
    index: int | None = None
    binding: str | None = None
    is_default: bool | None = Field(default=None, alias="isDefault")


class AssertionEncryptionSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    acs_endpoints: list[SamlAcsEndpoint] = Field(
        default_factory=list,
        alias="acsEndpoints",
    )


class SignOnSettings(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    idp_issuer: str | None = Field(default=None, alias="idpIssuer")
    sso_acs_url: str | None = Field(default=None, alias="ssoAcsUrl")
    sso_acs_url_override: str | None = Field(default=None, alias="ssoAcsUrlOverride")
    login_url: str | None = Field(default=None, alias="loginUrl")
    sp_issuer: str | None = Field(default=None, alias="spIssuer")
    audience: str | None = None
    audience_override: str | None = Field(default=None, alias="audienceOverride")
    recipient: str | None = None
    recipient_override: str | None = Field(default=None, alias="recipientOverride")
    destination: str | None = None
    destination_override: str | None = Field(default=None, alias="destinationOverride")
    subject_name_id_template: str | None = Field(
        default=None,
        alias="subjectNameIdTemplate",
    )
    subject_name_id_format: str | None = Field(
        default=None,
        alias="subjectNameIdFormat",
    )
    attribute_statements: list[dict] = Field(
        default_factory=list,
        alias="attributeStatements",
    )
    configured_attribute_statements: list[dict] = Field(
        default_factory=list,
        alias="configuredAttributeStatements",
    )
    acs_endpoints: list[SamlAcsEndpoint] = Field(
        default_factory=list,
        alias="acsEndpoints",
    )
    assertion_encryption: AssertionEncryptionSettings | None = Field(
        default=None,
        alias="assertionEncryption",
    )
    slo: dict | None = None


class Settings(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    app: dict | None = None
    notifications: dict | None = None
    manual_provisioning: bool | None = Field(default=None, alias="manualProvisioning")
    implicit_assignment: bool | None = Field(default=None, alias="implicitAssignment")
    em_opt_in_status: str | None = Field(default=None, alias="emOptInStatus")
    notes: dict | None = None
    oauth_client: OauthClientSettings | None = Field(default=None, alias="oauthClient")
    sign_on: SignOnSettings | None = Field(default=None, alias="signOn")


class OAuthCredential(BaseModel):
    auto_key_rotation: bool | None = Field(default=None, alias="autoKeyRotation")
    client_id: str | None = None
    token_endpoint_auth_method: str
    pkce_required: bool | None = None


class UserNameTemplate(BaseModel):
    template: str | None = None
    type: str | None = None


class Credentials(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    user_name_template: UserNameTemplate | None = Field(
        default=None, alias="userNameTemplate"
    )
    signing: dict | None = None
    oauth_client: OAuthCredential | None = Field(default=None, alias="oauthClient")


@app.asset(
    description="Okta application asset",
    node=NodeDef(
        icon="window-maximize",
        kind=nk.APPLICATION,
        description="Okta application node",
        properties=ApplicationProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.APPLICATION,
            kind=ek.CONTAINS,
            description="Organization contains application",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.IDP,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts another Okta organization for SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.JAMF_SSO_INTEGRATION,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts a Jamf tenant for SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.JAMF_SSO_INTEGRATION,
            kind=ek.ORG_SWA,
            description="Application stores credentials for a Jamf tenant",
            traversable=False,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GITHUB_ORGANIZATION,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts a GitHub organization for SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.ONE_PASSWORD_ACCOUNT,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts a 1Password account for SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.SNOWFLAKE_ACCOUNT,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts a Snowflake account for SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.AZ_TENANT,
            kind=ek.OUTBOUND_ORG_SSO,
            description="Application trusts an Entra tenant for SSO",
            traversable=True,
        ),
    ],
)
class Application(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    orn: str
    name: str
    label: str
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime
    sign_on_mode: str | None = Field(default=None, alias="signOnMode")
    credentials: Credentials | None = None
    settings: Settings | None = None
    features: list[str] = Field(default_factory=list)
    saml_metadata_entity_id: str | None = None
    saml_metadata_sso_url: str | None = None

    @property
    def _oauth_client_settings(self) -> OauthClientSettings | None:
        return self.settings.oauth_client if self.settings else None

    @property
    def _is_service_application(self) -> bool:
        oauth_client = self._oauth_client_settings
        return oauth_client is not None and oauth_client.application_type == "service"

    @property
    def _user_name_mapping(self) -> str | None:
        if self.sign_on_mode not in {"OPENID_CONNECT", "SAML_2_0", "SAML_1_1"}:
            return None

        if self.credentials and self.credentials.user_name_template:
            return self.credentials.user_name_template.template

        return None

    @property
    def _url(self) -> str | None:
        if self.sign_on_mode == "OPENID_CONNECT":
            oauth_client = self._oauth_client_settings
            if not oauth_client:
                return None

            return (
                oauth_client.initiate_login_uri
                if oauth_client.initiate_login_uri is not None
                else next(iter(oauth_client.redirect_uris), None)
            )

        sign_on = self.settings.sign_on if self.settings else None
        if self.sign_on_mode == "SAML_2_0":
            return sign_on.sso_acs_url if sign_on else None
        if self.sign_on_mode == "SAML_1_1":
            return sign_on.sso_acs_url_override if sign_on else None
        if self.sign_on_mode == "AUTO_LOGIN":
            return sign_on.login_url if sign_on else None
        if self.sign_on_mode in {
            "BROWSER_PLUGIN",
            "SECURE_PASSWORD_STORE",
            "BASIC_AUTH",
            "BOOKMARK",
        }:
            app_settings = self.settings.app if self.settings else None
            if app_settings:
                url = app_settings.get("url")
                return url if isinstance(url, str) else None

        return None

    @property
    def _app_setting_properties(self) -> dict[str, object]:
        app_settings = self.settings.app if self.settings else None
        if not app_settings:
            return {}

        if self.name == "active_directory":
            allowed_property_names = {"filter_groups_by_ou", "naming_context"}
        elif self.sign_on_mode in {
            "OPENID_CONNECT",
            "SAML_2_0",
            "SAML_1_1",
            "AUTO_LOGIN",
            "BROWSER_PLUGIN",
        }:
            allowed_property_names = APP_SETTING_PROPERTY_NAMES
        else:
            return {}

        properties: dict[str, object] = {}
        for key, value in app_settings.items():
            property_name = _snake_case_property_name(key)
            if property_name not in allowed_property_names:
                continue
            if _is_primitive_app_setting(value) or _is_homogeneous_primitive_list(
                value
            ):
                properties[property_name] = value

        return properties

    @property
    def as_node(self):
        display_name = self.label or self.name
        oauth_client = self._oauth_client_settings
        app_setting_properties = self._app_setting_properties
        oauth_scopes = self._lookup.application_oauth_scopes(self.id)
        return OktaNode(
            kinds=[nk.APPLICATION],
            properties=ApplicationProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=display_name,
                displayname=display_name,
                app_type=self.name,
                okta_domain=self._extras["tenant"],
                label=self.label,
                status=self.status,
                created=self.created,
                has_role_assignments=self._lookup.has_role_assignments(
                    self.id, "client"
                ),
                features=self.features,
                last_updated=self.last_updated,
                sign_on_mode=self.sign_on_mode,
                client_type=oauth_client.application_type if oauth_client else None,
                grant_types=oauth_client.grant_types if oauth_client else None,
                user_name_mapping=self._user_name_mapping,
                url=app_setting_properties.pop("url", self._url),
                oauth_scopes=list(oauth_scopes) or None,
                domain_sid=self._lookup.application_domain_sid(self.id)
                if self.name == "active_directory"
                else None,
                orn=self.orn,
                idp_id=app_setting_properties.pop("idp_id", None),
                environmentid=self._lookup.org_id(),
                **app_setting_properties,
            ),
        )

    @property
    def _outbound_trust_edge(self):
        edge_kind = hybrid_application_edge_kind(
            self.name,
            self.sign_on_mode,
            is_service=self._is_service_application,
        )
        if edge_kind is None:
            return

        app_settings = self.settings.app if self.settings else None
        target = outbound_trust_target(self.name, app_settings)
        if target is None:
            return

        yield Edge(
            kind=edge_kind,
            start=EdgePath(value=self.id, match_by="id"),
            end=hybrid_target_edge_path(target),
            properties=HybridAuthEdgeProperties(
                traversable=edge_kind == ek.OUTBOUND_ORG_SSO,
                mode=self.sign_on_mode,
            ),
        )

    # @property
    # def _kerberos_sso_edge(self):
    #     # TODO: matching against arrays needs to be supported by the BH API before this will
    #     # match with nodes
    #     if self.name == "active_directory":
    #         domain = self.label.split(".")[-2]
    #         end_spn = f"HTTP/{domain}.kerberos.okta.com"
    #         condition = PropertyMatch(key="serviceprincipalnames", value=end_spn)
    #         yield Edge(
    #             kind=ek.KERBEROS_SSO,
    #             start=ConditionalEdgePath(kind="User", property_matchers=[condition]),
    #             end=EdgePath(value=self.id, match_by="id"),
    #             properties=EdgeProperties(traversable=True),
    #         )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        # Disabled until BHE supports array-based matching
        # yield from self._kerberos_sso_edge
        yield from self._contains_edge
        yield from self._outbound_trust_edge
