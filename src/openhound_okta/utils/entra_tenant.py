"""Microsoft Entra tenant identification for Okta's Office 365 integration."""

import logging
import re
from collections.abc import Mapping
from typing import Any, Callable, Final
from urllib.parse import SplitResult, urlsplit

import requests
from dlt.sources.helpers import requests as dlt_requests

logger: Final[logging.Logger] = logging.getLogger(__name__)

OFFICE365_APP: Final[str] = "office365"
"""Okta app name of the Microsoft Office 365 integration."""

MICROSOFT_TENANT_ID_SETTING: Final[str] = "microsoftTenantId"
"""settings.app key holding the Entra tenant id GUID."""

MSFT_TENANT_SETTING: Final[str] = "msftTenant"
"""settings.app key holding the "Microsoft Tenant" name typed by the admin."""

MICROSOFT_LOGIN_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.windows.net",
        "sts.windows.net",
        # Azure Government (GCC High and DoD).
        "login.microsoftonline.us",
    }
)
"""Hosts of Microsoft's tenant-scoped endpoints, https://<host>/<tenant id>/..."""

ONMICROSOFT_DOMAIN_SUFFIX: Final[str] = ".onmicrosoft.com"
"""Suffix of the initial domain every Entra tenant is created with."""

OPENID_CONFIGURATION_URL: Final[str] = (
    "https://login.microsoftonline.com/{tenant}/.well-known/openid-configuration"
)
"""Tenant-scoped OpenID discovery document; {tenant} is a domain name or id."""


class EntraTenantIdResolver:
    """Add Entra tenant ids to Office 365 SAML 1.1 applications.

    Attached to the applications resource as a map step. Each distinct tenant
    is resolved once from Microsoft's OpenID configuration and the outcome is
    remembered, so an org with many Office 365 apps issues one request per
    tenant rather than one per app.

    Args:
        get: HTTP GET function; defaults to dlt's requests helper, which
            retries transient failures. Replaceable in tests.

    Attributes:
        TENANT_ID_PATTERN: Lowercase Entra tenant id GUID, which the OpenID
            configuration endpoint accepts in place of a domain name.
        _get: HTTP GET function used for the OpenID configuration requests.
        _tenant_ids: Resolved tenant id, or None when the lookup failed, per
            normalised domain name; the per-run cache.
    """

    TENANT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    )

    def __init__(
        self, get: Callable[..., requests.Response] = dlt_requests.get
    ) -> None:
        self._get: Callable[..., requests.Response] = get
        self._tenant_ids: dict[str, str | None] = {}

    def enrich(self, application: dict[str, Any]) -> dict[str, Any]:
        """Fill settings.app.microsoftTenantId on an Office 365 application.

        Applies only to the office365 app with SAML_1_1 sign-on that has an
        msftTenant but no microsoftTenantId.

        Args:
            application: Raw application record.

        Returns:
            The application, with settings.app.microsoftTenantId filled when
            resolved.
        """
        # Only the WS-Federation flavour of the Office 365 integration stores
        # the tenant as a bare msftTenant name; the OIDC flavour already carries
        # microsoftTenantId, and other apps have no Microsoft tenant at all.
        if (
            application.get("name") != OFFICE365_APP
            or application.get("signOnMode") != "SAML_1_1"
        ):
            return application

        # Raw API records: guard each nesting level rather than assume shape.
        settings: object = application.get("settings")
        if not isinstance(settings, Mapping):
            return application

        # settings.app holds the integration-specific fields, where the Office
        # 365 wizard stores the Microsoft tenant.
        app_settings: object = settings.get("app")
        if not isinstance(app_settings, Mapping):
            return application

        # Okta already supplied the id, so nothing to resolve.
        if app_settings.get(MICROSOFT_TENANT_ID_SETTING):
            return application

        # msftTenant is the "Microsoft Tenant" value typed by the admin; an
        # app with it missing or blank has nothing to look up.
        msft_tenant: object = app_settings.get(MSFT_TENANT_SETTING)
        if not isinstance(msft_tenant, str) or not msft_tenant.strip():
            return application

        # Calls Microsoft's OpenID configuration endpoint (once per tenant,
        # see resolve). An unresolvable tenant leaves the record as collected;
        # downstream hybrid matching then has no Entra tenant to pair the app
        # with.
        tenant_id: str | None = self.resolve(msft_tenant)
        if tenant_id is None:
            return application

        # Rebuild the nested mappings instead of mutating the record in place,
        # so the id lands in settings.app alongside Okta's own fields.
        enriched_app_settings: dict[str, Any] = {
            **app_settings,
            MICROSOFT_TENANT_ID_SETTING: tenant_id,
        }
        enriched_settings: dict[str, Any] = {**settings, "app": enriched_app_settings}
        return {**application, "settings": enriched_settings}

    def resolve(self, msft_tenant: str) -> str | None:
        """Return the tenant id for an msftTenant setting, one lookup per tenant.

        Args:
            msft_tenant: The application's msftTenant setting.

        Returns:
            The tenant id, or None if it could not be resolved.
        """
        # Cache on the normalised name so "contoso", "Contoso" and
        # "contoso.onmicrosoft.com" share one entry. Failures (None) are cached
        # too: dlt's client has already retried transient errors, and a
        # misconfigured value would otherwise fail and warn once per app.
        domain_name: str = self._domain_name(msft_tenant)
        if domain_name not in self._tenant_ids:
            self._tenant_ids[domain_name] = self._tenant_id_from_openid_configuration(
                domain_name
            )
        return self._tenant_ids[domain_name]

    @classmethod
    def tenant_id_from_url(cls, url: str) -> str | None:
        """Extract the tenant id from a tenant-scoped Microsoft endpoint URL.

        Microsoft's tenant-scoped endpoints have the form
        https://<host>/<tenant id>/<endpoint>, for example the token endpoint
        in an Office 365 OpenID configuration, an inbound Entra SAML identity
        provider's .../saml2 login URL, or an https://sts.windows.net/<id>/
        issuer.

        Args:
            url: Endpoint URL.

        Returns:
            The lowercase tenant id GUID, or None when the URL cannot be
            parsed, the host is not one of MICROSOFT_LOGIN_HOSTS, or the first
            path segment is not a GUID (such as "common", a domain name, or a
            bare .../saml2).
        """
        # An admin-configured IdP URL may be malformed; urlsplit raises on an
        # unbalanced bracket in the host, which is no tenant-scoped URL either.
        parts: SplitResult
        try:
            parts = urlsplit(url)
        except ValueError:
            return None

        # Exact host match: the URL may point anywhere, and a suffix check
        # would also accept a lookalike such as evilmicrosoftonline.com.
        hostname: str | None = parts.hostname
        if not hostname or hostname.lower() not in MICROSOFT_LOGIN_HOSTS:
            return None

        # The tenant is the first path segment; it must be a GUID so that
        # cloud-wide endpoints (/common/...) and endpoint names (/saml2) are
        # not mistaken for one.
        path_segments: list[str] = [
            segment for segment in parts.path.split("/") if segment
        ]
        if not path_segments:
            return None
        tenant_id: str = path_segments[0].lower()
        if not cls.TENANT_ID_PATTERN.fullmatch(tenant_id):
            return None
        return tenant_id

    @classmethod
    def _domain_name(cls, msft_tenant: str) -> str:
        """Turn an msftTenant setting into the name used to look the tenant up.

        Okta documents msftTenant as the tenant name without ".onmicrosoft.com",
        yet customer tenants had apps configured with the full domain, or with
        capital letters. Those may be misconfigurations on their side and
        possibly not even supported by Okta, but we still want to resolve them:
        the suffix is appended only to a bare prefix, and the name is lowercased
        so that every spelling of one tenant is looked up once.

        Args:
            msft_tenant: Tenant prefix such as "contoso", or a value the OpenID
                configuration endpoint accepts as is: a full domain name such
                as "contoso.onmicrosoft.com" or a tenant id GUID.

        Returns:
            A lowercase domain name or tenant id GUID.
        """
        # Microsoft treats the name case-insensitively; lowercasing just makes
        # every spelling of one tenant hit the same cache entry.
        tenant: str = msft_tenant.strip().lower()
        # A dot means the customer entered a full domain (onmicrosoft.com or a
        # verified custom one) and a GUID is a tenant id; the endpoint accepts
        # both as they are, and appending the suffix would break them.
        if "." in tenant or cls.TENANT_ID_PATTERN.fullmatch(tenant):
            return tenant
        # Otherwise it is the documented bare prefix.
        return f"{tenant}{ONMICROSOFT_DOMAIN_SUFFIX}"

    def _tenant_id_from_openid_configuration(self, domain_name: str) -> str | None:
        """Resolve an Entra tenant id from a domain name or tenant id GUID.

        Reads the tenant's OpenID configuration and takes the tenant id from
        the token endpoint path. Failures are logged and yield None.

        Args:
            domain_name: Domain name such as "contoso.onmicrosoft.com", or any
                other value the OpenID configuration endpoint accepts.

        Returns:
            The tenant id, or None if it could not be resolved.
        """
        # The tenant's OpenID discovery document is public and needs no auth.
        config_url: str = OPENID_CONFIGURATION_URL.format(tenant=domain_name)

        config: object
        try:
            # dlt's client retries 429/5xx and transport errors, then raises
            # the final HTTPError itself; raise_for_status also covers plain
            # GET functions injected by tests. A 400 for an unknown tenant is
            # not retried.
            response: requests.Response = self._get(config_url)
            response.raise_for_status()
            config = response.json()
        except (requests.RequestException, ValueError):
            logger.warning(
                "Unable to resolve Microsoft tenant ID for %s",
                domain_name,
                exc_info=True,
            )
            return None

        if not isinstance(config, Mapping):
            return None

        # The document has no tenant id field, but every endpoint URL in it is
        # tenant-scoped, so the token endpoint's tenant segment is the GUID.
        token_endpoint: object = config.get("token_endpoint")
        if not isinstance(token_endpoint, str):
            return None
        return self.tenant_id_from_url(token_endpoint)
