from dataclasses import dataclass, field as dc_field
from typing import Any

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek
from openhound_okta.kinds import nodes as nk
from openhound_okta.main import app


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _dedupe(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = _clean(value)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def saml_provider_id(app_id: str) -> str:
    return f"okta:saml:provider:{app_id}"


def saml_issuer_id(app_id: str) -> str:
    return f"okta:saml:issuer:{app_id}"


def saml_acs_id(app_id: str, index: int = 0) -> str:
    return f"okta:saml:acs:{app_id}:{index}"


def _sign_on(application) -> Any:
    settings = getattr(application, "settings", None)
    return getattr(settings, "sign_on", None)


def _app_settings(application) -> dict[str, Any]:
    settings = getattr(application, "settings", None)
    app_settings = getattr(settings, "app", None)
    return app_settings if isinstance(app_settings, dict) else {}


def _idp_issuer(application, sign_on: Any) -> str | None:
    return _clean(
        getattr(sign_on, "idp_issuer", None)
        or getattr(application, "saml_metadata_entity_id", None)
    )


def _sp_entity(sign_on: Any) -> str | None:
    slo = getattr(sign_on, "slo", None) or {}
    return _clean(
        getattr(sign_on, "sp_issuer", None)
        or getattr(sign_on, "audience", None)
        or getattr(sign_on, "audience_override", None)
        or slo.get("spIssuer")
    )


def _primary_acs_url(sign_on: Any) -> str | None:
    return _clean(
        getattr(sign_on, "sso_acs_url", None)
        or getattr(sign_on, "sso_acs_url_override", None)
        or getattr(sign_on, "recipient_override", None)
        or getattr(sign_on, "destination_override", None)
    )


def _github_oin_sp_route(application) -> tuple[str | None, str | None]:
    app_settings = _app_settings(application)
    app_name = getattr(application, "name", None)

    if app_name == "githubenterprisemanageduser":
        enterprise_name = _clean(app_settings.get("enterpriseName"))
        if enterprise_name:
            return (
                f"https://github.com/enterprises/{enterprise_name}/saml/consume",
                f"https://github.com/enterprises/{enterprise_name}",
            )

    if app_name == "githubcloud":
        org_name = _clean(app_settings.get("githubOrg") or app_settings.get("orgName"))
        if org_name:
            return (
                f"https://github.com/orgs/{org_name}/saml/consume",
                f"https://github.com/orgs/{org_name}",
            )

    return None, None


def _acs_endpoints(sign_on: Any) -> list[Any]:
    direct = list(getattr(sign_on, "acs_endpoints", None) or [])
    assertion_encryption = getattr(sign_on, "assertion_encryption", None)
    encrypted = list(getattr(assertion_encryption, "acs_endpoints", None) or [])
    return [*direct, *encrypted]


def is_saml_application(application) -> bool:
    return getattr(application, "sign_on_mode", None) == "SAML_2_0"


def saml_federation_provider_row(application) -> dict[str, Any] | None:
    sign_on = _sign_on(application)
    if not is_saml_application(application):
        return None
    idp_issuer = _idp_issuer(application, sign_on)
    acs_rows = saml_acs_rows(application)
    return {
        "id": saml_provider_id(application.id),
        "app_id": application.id,
        "app_name": application.name,
        "app_label": application.label,
        "app_status": application.status,
        "issuer_id": saml_issuer_id(application.id) if idp_issuer else None,
        "acs_ids": [row["id"] for row in acs_rows],
        "enabled": application.status == "ACTIVE",
    }


def saml_issuer_row(application) -> dict[str, Any] | None:
    sign_on = _sign_on(application)
    if not is_saml_application(application) or not sign_on:
        return None
    entity_id = _idp_issuer(application, sign_on)
    if not entity_id:
        return None
    return {
        "id": saml_issuer_id(application.id),
        "app_id": application.id,
        "app_name": application.name,
        "app_label": application.label,
        "entity_id": entity_id,
    }


def saml_acs_rows(application) -> list[dict[str, Any]]:
    sign_on = _sign_on(application)
    if not is_saml_application(application) or not sign_on:
        return []

    sp_entity_id = _sp_entity(sign_on)
    fallback_acs_url, fallback_sp_entity_id = _github_oin_sp_route(application)
    if not sp_entity_id:
        sp_entity_id = fallback_sp_entity_id
    rows: list[dict[str, Any]] = []
    route_keys: set[tuple[str, str]] = set()
    primary_acs_url = _primary_acs_url(sign_on) or fallback_acs_url
    if primary_acs_url and sp_entity_id:
        route_keys.add((primary_acs_url, sp_entity_id))
        rows.append(
            {
                "id": saml_acs_id(application.id, 0),
                "app_id": application.id,
                "app_name": application.name,
                "app_label": application.label,
                "acs_url": primary_acs_url,
                "sp_entity_id": sp_entity_id,
                "index": 0,
                "binding": None,
                "is_default": True,
            }
        )

    for endpoint in _acs_endpoints(sign_on):
        acs_url = _clean(getattr(endpoint, "url", None))
        if not acs_url or not sp_entity_id:
            continue
        route_key = (acs_url, sp_entity_id)
        if route_key in route_keys:
            continue
        endpoint_index = getattr(endpoint, "index", None)
        index = int(endpoint_index) if endpoint_index is not None else len(rows)
        row = {
            "id": saml_acs_id(application.id, index),
            "app_id": application.id,
            "app_name": application.name,
            "app_label": application.label,
            "acs_url": acs_url,
            "sp_entity_id": sp_entity_id,
            "index": index,
            "binding": _clean(getattr(endpoint, "binding", None)),
            "is_default": getattr(endpoint, "is_default", None),
        }
        if row["id"] not in {existing["id"] for existing in rows}:
            route_keys.add(route_key)
            rows.append(row)

    return rows


def saml_match_values(*values: str | None) -> list[str]:
    return _dedupe(list(values))


@dataclass
class SamlFederationProviderProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML federation provider.

    Attributes:
        app_id: The Okta application ID that implements the provider.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        app_status: The Okta application lifecycle status.
        enabled: Whether the application is active.
    """

    app_id: str
    app_name: str
    app_label: str
    app_status: str
    enabled: bool


@dataclass
class SamlIssuerProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML issuer.

    Attributes:
        app_id: The Okta application ID that owns the issuer.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        entity_id: The byte-exact SAML issuer entity ID.
    """

    app_id: str
    app_name: str
    app_label: str
    entity_id: str


@dataclass
class SamlAssertionConsumerServiceProperties(OktaNodeProperties):
    """Properties for a normalized Okta-targeted SAML ACS route.

    Attributes:
        app_id: The Okta application ID that owns the ACS route.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        acs_url: The byte-exact SAML assertion consumer service URL.
        sp_entity_id: The byte-exact SAML service provider entity ID.
        index: The ACS endpoint index from Okta.
        binding: The SAML binding for this ACS endpoint, when present.
        is_default: Whether Okta marks this ACS endpoint as default.
    """

    app_id: str
    app_name: str
    app_label: str
    acs_url: str
    sp_entity_id: str
    index: int
    binding: str | None = None
    is_default: bool | None = None


@dataclass
class SamlMatchValuesEdgeProperties(EdgeProperties):
    """Properties for normalized Okta SAML match-value edges.

    Attributes:
        match_values: Identity values Okta can assert for the assignment.
    """

    match_values: list[str] = dc_field(default_factory=list)


@app.asset(
    node=NodeDef(
        icon="id-card",
        kind=nk.SAML_FEDERATION_PROVIDER,
        description="Normalized SAML federation provider implemented by an Okta SAML app",
        properties=SamlFederationProviderProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.SAML_FEDERATION_PROVIDER,
            kind=ek.SAML_IMPLEMENTS,
            description="Okta application implements a normalized SAML provider",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_ISSUER,
            kind=ek.SAML_ISSUES_AS,
            description="SAML provider issues assertions as an issuer entity ID",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_ASSERTION_CONSUMER_SERVICE,
            kind=ek.SAML_ISSUES_ASSERTIONS_TO,
            description="SAML provider issues assertions to an SP ACS route",
            traversable=False,
        ),
    ],
)
class SamlFederationProvider(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    app_status: str
    issuer_id: str | None = None
    acs_ids: list[str] = Field(default_factory=list)
    enabled: bool

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_FEDERATION_PROVIDER],
            properties=SamlFederationProviderProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.app_name,
                displayname=self.app_label or self.app_name,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                app_status=self.app_status,
                enabled=self.enabled,
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.SAML_IMPLEMENTS,
            start=EdgePath(value=self.app_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
        if self.issuer_id:
            yield Edge(
                kind=ek.SAML_ISSUES_AS,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.issuer_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
        for acs_id in self.acs_ids:
            yield Edge(
                kind=ek.SAML_ISSUES_ASSERTIONS_TO,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=acs_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )


@app.asset(
    node=NodeDef(
        icon="key-round",
        kind=nk.SAML_ISSUER,
        description="Normalized SAML issuer entity ID for an Okta SAML app",
        properties=SamlIssuerProperties,
    ),
)
class SamlIssuer(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    entity_id: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ISSUER],
            properties=SamlIssuerProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.entity_id,
                displayname=self.entity_id,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                entity_id=self.entity_id,
            ),
        )

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        icon="route",
        kind=nk.SAML_ASSERTION_CONSUMER_SERVICE,
        description="Normalized SAML ACS route for an Okta SAML app",
        properties=SamlAssertionConsumerServiceProperties,
    ),
)
class SamlAssertionConsumerService(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    acs_url: str
    sp_entity_id: str
    index: int
    binding: str | None = None
    is_default: bool | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_ASSERTION_CONSUMER_SERVICE],
            properties=SamlAssertionConsumerServiceProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.acs_url,
                displayname=self.acs_url,
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                acs_url=self.acs_url,
                sp_entity_id=self.sp_entity_id,
                index=self.index,
                binding=self.binding,
                is_default=self.is_default,
            ),
        )

    @property
    def edges(self):
        return iter(())
