"""Safe graph-expression contract for OIN route application settings."""

import re


APP_SETTING_PROPERTY_ALIASES = {
    "acsurl": "acs_url",
    "aud_uri": "audience_uri",
    "subdomain": "sub_domain",
}

DIRECT_SAML_ROUTE_APP_SETTING_PROPERTIES = frozenset(
    {
        "acs_url",
        "audience",
        "audience_restriction",
        "audience_uri",
        "custom_acs_url",
        "custom_entity_id",
        "destination",
        "entity_id",
        "recipient",
        "sp_entity_id",
        "sso_url",
    }
)

RESOLVER_SELECTOR_APP_SETTING_PROPERTIES = frozenset(
    {
        "aud_restriction",
        "base_url",
        "domain",
        "enterprise_name",
        "github_org",
        "org_name",
        "sub_domain",
    }
)

SAML_ROUTE_APP_SETTING_PROPERTIES = (
    DIRECT_SAML_ROUTE_APP_SETTING_PROPERTIES | RESOLVER_SELECTOR_APP_SETTING_PROPERTIES
)

# Raw resolver fields may be listed here only with a reviewable reason when
# graph expression would be unsafe. Bundled resolvers currently need no exception.
COLLECTION_TIME_ONLY_RESOLVER_APP_FIELDS: dict[str, str] = {}


def snake_case_app_setting_property_name(name: str) -> str:
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return name.replace("-", "_").lower()


def canonical_app_setting_property_name(name: str) -> str:
    property_name = snake_case_app_setting_property_name(name)
    return APP_SETTING_PROPERTY_ALIASES.get(property_name, property_name)
