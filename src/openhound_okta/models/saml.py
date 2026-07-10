from dataclasses import dataclass, field as dc_field
import json
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


def saml_claim_mapping_id(app_id: str, index: int = 0) -> str:
    return f"okta:saml:claim-mapping:{app_id}:{index}"


def saml_service_provider_id(idp_id: str) -> str:
    return f"okta:saml:service-provider:{idp_id}"


def saml_trusted_issuer_id(idp_id: str) -> str:
    return f"okta:saml:trusted-issuer:{idp_id}"


def saml_sp_acs_id(idp_id: str, index: int = 0) -> str:
    return f"okta:saml:sp-acs:{idp_id}:{index}"


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


def _field_value(source: Any, field_name: str) -> str | None:
    return _clean(getattr(source, field_name, None))


def _profile_value(profile: Any, field_name: str) -> str | None:
    return _field_value(profile, field_name) if profile else None


def _template_field(template: str | None) -> str | None:
    value = _clean(template)
    if not value:
        return None
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    return value


def _application_user_value(template: str | None, application_user: Any) -> str | None:
    field = _template_field(template)
    credentials = getattr(application_user, "credentials", None)
    profile = getattr(application_user, "profile", None)
    username = _field_value(credentials, "username") if credentials else None

    if not field:
        return username
    if field in {"appuser.userName", "source.login", "user.login"}:
        return username or _profile_value(profile, "login")
    if field in {"source.email", "user.email"}:
        return _profile_value(profile, "email")
    if field in {"source.firstName", "user.firstName"}:
        return _profile_value(profile, "first_name")
    if field in {"source.lastName", "user.lastName"}:
        return _profile_value(profile, "last_name")
    return None


def _idp_user_value(template: str | None, idp_user: Any) -> str | None:
    field = _template_field(template)
    profile = getattr(idp_user, "profile", None)

    if not field:
        return None
    if field == "idpuser.email":
        return _profile_value(profile, "email")
    if field == "idpuser.subjectNameId":
        return _profile_value(profile, "subject_name_id")
    if field == "idpuser.subjectNameQualifier":
        return _profile_value(profile, "subject_name_qualifier")
    if field == "idpuser.subjectNameId + '@' + idpuser.subjectNameQualifier":
        subject = _profile_value(profile, "subject_name_id")
        qualifier = _profile_value(profile, "subject_name_qualifier")
        if subject and qualifier:
            return f"{subject}@{qualifier}"
    return None


def saml_application_match_values(application_user: Any) -> list[str]:
    return _dedupe(
        [
            _application_user_value(
                getattr(application_user, "app_subject_name_id_template", None),
                application_user,
            ),
            _application_user_value(
                getattr(application_user, "app_user_name_template", None),
                application_user,
            ),
        ]
    )


def saml_idp_user_match_values(idp_user: Any) -> list[str]:
    return _dedupe(
        [
            _idp_user_value(
                getattr(idp_user, "idp_subject_user_name_template", None),
                idp_user,
            )
        ]
    )


def saml_match_source(template: str | None) -> str | None:
    return _template_field(template)


def _statement_value(statement: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = statement.get(key)
        if isinstance(value, list):
            cleaned = _dedupe([str(item) for item in value])
            if cleaned:
                return ",".join(cleaned)
        cleaned = _clean(value)
        if cleaned:
            return cleaned
    return None


def _statement_expression(statement: dict[str, Any]) -> str | None:
    value = _statement_value(
        statement,
        "value",
        "expression",
        "filterValue",
        "values",
        "attributeValue",
    )
    if value:
        return value
    if statement:
        return json.dumps(statement, sort_keys=True, separators=(",", ":"))
    return None


def is_saml_application(application) -> bool:
    return getattr(application, "sign_on_mode", None) == "SAML_2_0"


def is_saml_identity_provider(identity_provider) -> bool:
    protocol = getattr(identity_provider, "protocol", None)
    return (
        getattr(identity_provider, "type", None) == "SAML2"
        and getattr(protocol, "type", None) == "SAML2"
    )


def _idp_trust(identity_provider) -> Any:
    protocol = getattr(identity_provider, "protocol", None)
    credentials = getattr(protocol, "credentials", None)
    return getattr(credentials, "trust", None)


def _trusted_issuer(identity_provider) -> str | None:
    return _clean(getattr(_idp_trust(identity_provider), "issuer", None))


def _trusted_audience(identity_provider) -> str | None:
    return _clean(getattr(_idp_trust(identity_provider), "audience", None))


def _idp_acs_url(identity_provider) -> str | None:
    links = getattr(identity_provider, "links", None) or {}
    acs = links.get("acs") if isinstance(links, dict) else None
    if isinstance(acs, dict):
        return _clean(acs.get("href"))
    return _clean(getattr(acs, "href", None))


def saml_federation_provider_row(application) -> dict[str, Any] | None:
    sign_on = _sign_on(application)
    if not is_saml_application(application):
        return None
    idp_issuer = _idp_issuer(application, sign_on)
    acs_rows = saml_acs_rows(application)
    claim_mapping_rows = saml_claim_mapping_rows(application)
    return {
        "id": saml_provider_id(application.id),
        "app_id": application.id,
        "app_name": application.name,
        "app_label": application.label,
        "app_status": application.status,
        "issuer_id": saml_issuer_id(application.id) if idp_issuer else None,
        "acs_ids": [row["id"] for row in acs_rows],
        "claim_mapping_ids": [row["id"] for row in claim_mapping_rows],
        "enabled": application.status == "ACTIVE",
    }


def saml_claim_mapping_rows(application) -> list[dict[str, Any]]:
    sign_on = _sign_on(application)
    if not is_saml_application(application) or not sign_on:
        return []

    rows: list[dict[str, Any]] = []
    subject_template = _clean(getattr(sign_on, "subject_name_id_template", None))
    user_name_template = None
    credentials = getattr(application, "credentials", None)
    user_name_template_value = getattr(credentials, "user_name_template", None)
    if isinstance(user_name_template_value, dict):
        user_name_template = _clean(user_name_template_value.get("template"))

    if subject_template or user_name_template:
        rows.append(
            {
                "id": saml_claim_mapping_id(application.id, len(rows)),
                "app_id": application.id,
                "app_name": application.name,
                "app_label": application.label,
                "claim_name": "NameID",
                "mapping_type": "name_id",
                "source_property": saml_match_source(
                    subject_template or user_name_template
                ),
                "expression": subject_template or user_name_template,
                "name_id_format": _clean(
                    getattr(sign_on, "subject_name_id_format", None)
                ),
            }
        )

    statements = [
        ("attribute", item)
        for item in getattr(sign_on, "attribute_statements", None) or []
    ]
    statements.extend(
        [
            ("configured_attribute", item)
            for item in getattr(sign_on, "configured_attribute_statements", None) or []
        ]
    )
    for mapping_type, statement in statements:
        if not isinstance(statement, dict):
            continue
        expression = _statement_expression(statement)
        claim_name = _statement_value(statement, "name", "attributeName", "type")
        if not expression and not claim_name:
            continue
        rows.append(
            {
                "id": saml_claim_mapping_id(application.id, len(rows)),
                "app_id": application.id,
                "app_name": application.name,
                "app_label": application.label,
                "claim_name": claim_name or "attribute",
                "mapping_type": mapping_type,
                "source_property": saml_match_source(expression),
                "expression": expression,
                "name_id_format": None,
            }
        )

    return rows


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
        "source_object_kind": nk.APPLICATION,
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
                "source_object_kind": nk.APPLICATION,
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
            "source_object_kind": nk.APPLICATION,
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


def saml_service_provider_row(identity_provider) -> dict[str, Any] | None:
    if not is_saml_identity_provider(identity_provider):
        return None

    issuer = _trusted_issuer(identity_provider)
    acs_rows = saml_sp_acs_rows(identity_provider)
    return {
        "id": saml_service_provider_id(identity_provider.id),
        "idp_id": identity_provider.id,
        "idp_name": identity_provider.name,
        "idp_type": identity_provider.type,
        "idp_status": identity_provider.status,
        "sp_entity_id": _trusted_audience(identity_provider),
        "issuer_id": saml_trusted_issuer_id(identity_provider.id) if issuer else None,
        "acs_ids": [row["id"] for row in acs_rows],
        "enabled": identity_provider.status == "ACTIVE",
    }


def saml_trusted_issuer_row(identity_provider) -> dict[str, Any] | None:
    if not is_saml_identity_provider(identity_provider):
        return None
    entity_id = _trusted_issuer(identity_provider)
    if not entity_id:
        return None
    return {
        "id": saml_trusted_issuer_id(identity_provider.id),
        "app_id": identity_provider.id,
        "app_name": identity_provider.name,
        "app_label": identity_provider.name,
        "source_object_kind": nk.IDP,
        "entity_id": entity_id,
    }


def saml_sp_acs_rows(identity_provider) -> list[dict[str, Any]]:
    if not is_saml_identity_provider(identity_provider):
        return []

    acs_url = _idp_acs_url(identity_provider)
    sp_entity_id = _trusted_audience(identity_provider)
    if not acs_url or not sp_entity_id:
        return []

    return [
        {
            "id": saml_sp_acs_id(identity_provider.id, 0),
            "app_id": identity_provider.id,
            "app_name": identity_provider.name,
            "app_label": identity_provider.name,
            "source_object_kind": nk.IDP,
            "acs_url": acs_url,
            "sp_entity_id": sp_entity_id,
            "index": 0,
            "binding": _clean(
                getattr(
                    getattr(identity_provider.protocol.endpoints, "acs", None),
                    "binding",
                    None,
                )
            ),
            "is_default": True,
        }
    ]


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
        source_object_kind: The native OpenGraph kind that owns this SAML issuer.
        entity_id: The byte-exact SAML issuer entity ID.
    """

    app_id: str
    app_name: str
    app_label: str
    entity_id: str
    source_object_kind: str = nk.APPLICATION


@dataclass
class SamlAssertionConsumerServiceProperties(OktaNodeProperties):
    """Properties for a normalized Okta-targeted SAML ACS route.

    Attributes:
        app_id: The Okta application ID that owns the ACS route.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        source_object_kind: The native OpenGraph kind that owns this ACS route.
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
    source_object_kind: str = nk.APPLICATION
    binding: str | None = None
    is_default: bool | None = None


@dataclass
class SamlServiceProviderProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML service provider.

    Attributes:
        idp_id: The Okta identity provider ID that implements the SP role.
        idp_name: The Okta identity provider display name.
        idp_type: The Okta identity provider type.
        idp_status: The Okta identity provider lifecycle status.
        sp_entity_id: The byte-exact Okta SP entity ID or audience.
        enabled: Whether the identity provider is active.
    """

    idp_id: str
    idp_name: str
    idp_type: str
    idp_status: str
    sp_entity_id: str | None = None
    enabled: bool = False


@dataclass
class SamlClaimMappingProperties(OktaNodeProperties):
    """Properties for a normalized Okta SAML claim mapping.

    Attributes:
        app_id: The Okta application ID that owns the claim mapping.
        app_name: The Okta application internal name.
        app_label: The Okta application display label.
        claim_name: The SAML claim or NameID slot being populated.
        mapping_type: The Okta mapping source, such as name_id or attribute.
        source_property: The portable source field name when it can be resolved.
        expression: The raw Okta expression or statement payload.
        name_id_format: The requested SAML NameID format when the mapping is NameID.
    """

    app_id: str
    app_name: str
    app_label: str
    claim_name: str
    mapping_type: str
    source_property: str | None = None
    expression: str | None = None
    name_id_format: str | None = None


@dataclass
class SamlMatchValuesEdgeProperties(EdgeProperties):
    """Properties for normalized Okta SAML match-value edges.

    Attributes:
        match_values: Identity values Okta can assert for the assignment.
        source_property: The Okta field or expression source for the match values.
    """

    match_values: list[str] = dc_field(default_factory=list)
    source_property: str | None = None


@dataclass
class SamlAccountEdgeProperties(SamlMatchValuesEdgeProperties):
    """Properties for normalized Okta SAML service-provider account edges.

    Attributes:
        match_values: Concrete values accepted for SAML account matching.
        source_property: The Okta IdP user field used to resolve match values.
        account_state: Account reachability state when known.
    """

    account_state: str | None = None


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
        EdgeDef(
            start=nk.SAML_FEDERATION_PROVIDER,
            end=nk.SAML_CLAIM_MAPPING,
            kind=ek.SAML_HAS_CLAIM_MAPPING,
            description="SAML provider has a claim mapping explanation",
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
    claim_mapping_ids: list[str] = Field(default_factory=list)
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
        for claim_mapping_id in self.claim_mapping_ids:
            yield Edge(
                kind=ek.SAML_HAS_CLAIM_MAPPING,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=claim_mapping_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )


@app.asset(
    node=NodeDef(
        icon="split",
        kind=nk.SAML_CLAIM_MAPPING,
        description="Normalized SAML claim mapping for an Okta SAML app",
        properties=SamlClaimMappingProperties,
    ),
)
class SamlClaimMapping(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    app_id: str
    app_name: str
    app_label: str
    claim_name: str
    mapping_type: str
    source_property: str | None = None
    expression: str | None = None
    name_id_format: str | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_CLAIM_MAPPING],
            properties=SamlClaimMappingProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=f"{self.app_name}:{self.claim_name}",
                displayname=f"{self.app_label}:{self.claim_name}",
                environmentid=self._lookup.org_id(),
                app_id=self.app_id,
                app_name=self.app_name,
                app_label=self.app_label,
                claim_name=self.claim_name,
                mapping_type=self.mapping_type,
                source_property=self.source_property,
                expression=self.expression,
                name_id_format=self.name_id_format,
            ),
        )

    @property
    def edges(self):
        return iter(())


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
    source_object_kind: str = nk.APPLICATION

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
                source_object_kind=self.source_object_kind,
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
    source_object_kind: str = nk.APPLICATION
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
                source_object_kind=self.source_object_kind,
                binding=self.binding,
                is_default=self.is_default,
            ),
        )

    @property
    def edges(self):
        return iter(())


@app.asset(
    node=NodeDef(
        icon="plug",
        kind=nk.SAML_SERVICE_PROVIDER,
        description="Normalized SAML service provider implemented by an Okta inbound IdP",
        properties=SamlServiceProviderProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.IDP,
            end=nk.SAML_SERVICE_PROVIDER,
            kind=ek.SAML_IMPLEMENTS,
            description="Okta identity provider implements a normalized SAML service provider",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ISSUER,
            kind=ek.SAML_TRUSTS_ISSUER,
            description="SAML service provider trusts an issuer entity ID",
            traversable=False,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.SAML_ASSERTION_CONSUMER_SERVICE,
            kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
            description="SAML service provider owns an ACS route",
            traversable=False,
        ),
    ],
)
class SamlServiceProvider(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    idp_id: str
    idp_name: str
    idp_type: str
    idp_status: str
    sp_entity_id: str | None = None
    issuer_id: str | None = None
    acs_ids: list[str] = Field(default_factory=list)
    enabled: bool

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.SAML_SERVICE_PROVIDER],
            properties=SamlServiceProviderProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.idp_name,
                displayname=self.idp_name,
                environmentid=self._lookup.org_id(),
                idp_id=self.idp_id,
                idp_name=self.idp_name,
                idp_type=self.idp_type,
                idp_status=self.idp_status,
                sp_entity_id=self.sp_entity_id,
                enabled=self.enabled,
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.SAML_IMPLEMENTS,
            start=EdgePath(value=self.idp_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
        if self.issuer_id:
            yield Edge(
                kind=ek.SAML_TRUSTS_ISSUER,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.issuer_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
        for acs_id in self.acs_ids:
            yield Edge(
                kind=ek.SAML_HAS_ASSERTION_CONSUMER_SERVICE,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=acs_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
