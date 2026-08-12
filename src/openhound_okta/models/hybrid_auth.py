from dataclasses import dataclass
from urllib.parse import urlparse

from openhound.core.models.entries_dataclass import (
    ConditionalEdgePath,
    EdgePath,
    EdgeProperties,
    PropertyMatch,
)

from openhound_okta.kinds import edges as ek, nodes as nk

ACTIVE_DIRECTORY_APP = "active_directory"
LDAP_INTERFACE_APP = "ldap_interface"
OKTA_ORG2ORG_APP = "okta_org2org"
JAMF_SAML_APP = "jamfsoftwareserver"
JAMF_SWA_APP = "casper"
GITHUB_CLOUD_APP = "githubcloud"
ONE_PASSWORD_BUSINESS_APP = "1password_business"
SNOWFLAKE_APP = "snowflake"
OFFICE365_APP = "office365"

SUPPORTED_HYBRID_AUTH_APPS = frozenset(
    {
        OKTA_ORG2ORG_APP,
        JAMF_SAML_APP,
        JAMF_SWA_APP,
        GITHUB_CLOUD_APP,
        ONE_PASSWORD_BUSINESS_APP,
        SNOWFLAKE_APP,
        OFFICE365_APP,
    }
)

SAML_SIGN_ON_MODES = frozenset({"SAML_2_0", "SAML_1_1", "WS_FEDERATION"})
OIDC_SIGN_ON_MODES = frozenset({"OPENID_CONNECT"})
SWA_SIGN_ON_MODES = frozenset({"AUTO_LOGIN", "BASIC_AUTH", "BROWSER_PLUGIN"})


@dataclass(frozen=True)
class HybridTarget:
    """A cross-collector node match used by OktaHound hybrid auth edges."""

    kind: str
    match_by: str
    value: str | None = None
    property_matchers: tuple[tuple[str, str], ...] = ()

    @classmethod
    def by_id(cls, kind: str, value: str | None) -> "HybridTarget | None":
        if _is_missing_match_value(value):
            return None
        return cls(kind=kind, match_by="id", value=value)

    @classmethod
    def by_name(cls, kind: str, value: str | None) -> "HybridTarget | None":
        if _is_missing_match_value(value):
            return None
        return cls(kind=kind, match_by="name", value=value)

    @classmethod
    def by_properties(
        cls, kind: str, property_matchers: tuple[tuple[str, str | None], ...]
    ) -> "HybridTarget | None":
        if any(_is_missing_match_value(value) for _, value in property_matchers):
            return None
        return cls(
            kind=kind,
            match_by="property",
            property_matchers=tuple(
                (key, value) for key, value in property_matchers if value is not None
            ),
        )


def _is_missing_match_value(value: str | None) -> bool:
    return value is None or not value.strip()


def _uppercase_match_value(value: str | None) -> str | None:
    return value.upper() if value is not None else None


@dataclass
class HybridAuthEdgeProperties(EdgeProperties):
    """OktaHound hybrid auth edges carry the Okta sign-on mode."""

    mode: str | None = None


def hybrid_target_edge_path(target: HybridTarget) -> EdgePath | ConditionalEdgePath:
    """Translate OktaHound target semantics into OpenHound edge paths.

    OpenHound currently supports `id` and `property` edge paths, while OktaHound
    also emits `match_by: name`. A name target is therefore represented as a
    single-property `name` matcher without expanding the identity criteria.
    """

    if target.match_by == "id":
        if target.value is None:
            raise ValueError("HybridTarget value is required for id matches")
        return EdgePath(value=target.value, match_by="id")

    if target.match_by == "name":
        if target.value is None:
            raise ValueError("HybridTarget value is required for name matches")
        return ConditionalEdgePath(
            kind=target.kind,
            property_matchers=[
                PropertyMatch(key="name", value=_uppercase_match_value(target.value))
            ],
        )

    if target.match_by == "property":
        return ConditionalEdgePath(
            kind=target.kind,
            property_matchers=[
                PropertyMatch(key=key, value=value)
                for key, value in target.property_matchers
            ],
        )

    raise ValueError(f"Unsupported HybridTarget match mode: {target.match_by}")


def is_saml_application(sign_on_mode: str | None) -> bool:
    return sign_on_mode in SAML_SIGN_ON_MODES


def is_oidc_application(sign_on_mode: str | None) -> bool:
    return sign_on_mode in OIDC_SIGN_ON_MODES


def is_swa_application(sign_on_mode: str | None) -> bool:
    return sign_on_mode in SWA_SIGN_ON_MODES


def hybrid_user_sign_on_edge_kind(sign_on_mode: str | None) -> str | None:
    if is_saml_application(sign_on_mode) or is_oidc_application(sign_on_mode):
        return ek.OUTBOUND_SSO
    if is_swa_application(sign_on_mode):
        return ek.SWA
    return None


def hybrid_application_edge_kind(
    app_name: str,
    sign_on_mode: str | None,
    *,
    is_service: bool = False,
) -> str | None:
    if app_name in {ACTIVE_DIRECTORY_APP, LDAP_INTERFACE_APP} or is_service:
        return None
    if is_saml_application(sign_on_mode) or is_oidc_application(sign_on_mode):
        return ek.OUTBOUND_ORG_SSO
    if is_swa_application(sign_on_mode):
        return ek.ORG_SWA
    return None


def one_password_domain(sub_domain: str | None, region_type: str | None) -> str | None:
    if sub_domain is None or region_type is None:
        return None
    return f"{sub_domain}.1password.{region_type}"


def okta_org2org_domain(base_url: str | None) -> str | None:
    if base_url is None:
        return None
    parsed = urlparse(base_url)
    return parsed.hostname if parsed.scheme and parsed.hostname else None


def outbound_trust_target(
    app_name: str, app_settings: dict | None
) -> HybridTarget | None:
    settings = app_settings or {}

    if app_name == OKTA_ORG2ORG_APP:
        return HybridTarget.by_id(nk.IDP, _uppercase_match_value(settings.get("idpId")))
    if app_name in {JAMF_SAML_APP, JAMF_SWA_APP}:
        domain = settings.get("domain")
        if _is_missing_match_value(domain):
            return None
        return HybridTarget.by_id(
            nk.JAMF_SSO_INTEGRATION,
            _uppercase_match_value(f"{domain}-SSO"),
        )
    if app_name == GITHUB_CLOUD_APP:
        return HybridTarget.by_name(nk.GITHUB_ORGANIZATION, settings.get("githubOrg"))
    if app_name == ONE_PASSWORD_BUSINESS_APP:
        domain = one_password_domain(settings.get("subDomain"), settings.get("regionType"))
        if not domain:
            return None
        return HybridTarget.by_properties(
            nk.ONE_PASSWORD_ACCOUNT,
            (("domain", domain),),
        )
    if app_name == SNOWFLAKE_APP:
        sub_domain = settings.get("subDomain")
        return HybridTarget.by_id(
            nk.SNOWFLAKE_ACCOUNT,
            sub_domain.upper() if sub_domain is not None else None,
        )
    if app_name == OFFICE365_APP:
        return HybridTarget.by_id(
            nk.AZ_TENANT,
            _uppercase_match_value(settings.get("microsoftTenantId")),
        )
    return None


def hybrid_user_target(
    app_name: str,
    app_settings: dict | None,
    *,
    target_user_name: str | None,
    external_id: str | None = None,
) -> HybridTarget | None:
    settings = app_settings or {}

    if app_name == OKTA_ORG2ORG_APP:
        return HybridTarget.by_id(nk.USER, _uppercase_match_value(external_id))
    if app_name in {JAMF_SAML_APP, JAMF_SWA_APP}:
        return HybridTarget.by_properties(
            nk.JAMF_ACCOUNT,
            (("email", target_user_name), ("tenant", settings.get("domain"))),
        )
    if app_name == GITHUB_CLOUD_APP:
        return HybridTarget.by_properties(
            nk.GITHUB_USER,
            (
                ("login", target_user_name),
                ("environment_name", settings.get("githubOrg")),
            ),
        )
    if app_name == ONE_PASSWORD_BUSINESS_APP:
        account_name = one_password_domain(
            settings.get("subDomain"), settings.get("regionType")
        )
        if not target_user_name or not account_name:
            return None
        return HybridTarget.by_properties(
            nk.ONE_PASSWORD_USER,
            (
                ("email", target_user_name),
                ("account_name", account_name),
            ),
        )
    if app_name == SNOWFLAKE_APP:
        sub_domain = settings.get("subDomain")
        if sub_domain is None or target_user_name is None:
            return None
        return HybridTarget.by_id(
            nk.SNOWFLAKE_USER, f"{sub_domain}.{target_user_name}".upper()
        )
    if app_name == OFFICE365_APP:
        return HybridTarget.by_properties(
            nk.AZ_USER,
            (
                ("userprincipalname", target_user_name),
                ("tenantid", _uppercase_match_value(settings.get("microsoftTenantId"))),
            ),
        )
    return None


def hybrid_group_target(
    app_name: str,
    app_settings: dict | None,
    *,
    group_name: str | None,
) -> HybridTarget | None:
    """Build the external group matcher used by OktaHound sync edges."""

    settings = app_settings or {}

    if app_name == ACTIVE_DIRECTORY_APP:
        return HybridTarget.by_properties(
            nk.AD_GROUP,
            (
                ("samaccountname", group_name),
                ("domain", settings.get("namingContext")),
            ),
        )
    if app_name == OKTA_ORG2ORG_APP:
        return HybridTarget.by_properties(
            nk.GROUP,
            (
                ("displayname", group_name),
                ("okta_domain", okta_org2org_domain(settings.get("baseUrl"))),
            ),
        )
    if app_name == OFFICE365_APP:
        return HybridTarget.by_properties(
            nk.AZ_GROUP,
            (
                ("displayname", group_name),
                ("tenantid", _uppercase_match_value(settings.get("microsoftTenantId"))),
            ),
        )
    return None
