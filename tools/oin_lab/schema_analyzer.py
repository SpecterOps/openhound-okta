"""Normalize Okta OIN catalog schemas for route-focused research.

The analyzer deliberately reports structural signals rather than deriving SAML
routes. A schema field, description, or default is a research lead until it is
corroborated by authoritative documentation or controlled live observations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html.parser import HTMLParser
import re
from typing import Any


SCHEMA_ANALYSIS_VERSION = 1
_APP_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_SENSITIVE_ATTRIBUTE = re.compile(
    r"(?:password|passphrase|secret|token|certificate|private.?key|api.?key|"
    r"access.?key|credential|encrypted)",
    re.IGNORECASE,
)
_EXPLICIT_ROUTE_TEXT = re.compile(
    r"\b(?:acs|assertion consumer(?: service)?|audience(?: restriction)?|"
    r"entity id|service provider (?:id|url)|sp (?:id|url)|recipient(?: url)?|"
    r"destination(?: url)?|post[ -]?back url)\b",
    re.IGNORECASE,
)
_ROUTE_ORIGIN_TEXT = re.compile(
    r"\b(?:base|site|host|instance|root) url\b", re.IGNORECASE
)
_DEFAULT_ROUTE_HINT = re.compile(
    r"\bdefault\b.*(?:https?://|\b(?:acs|url|uri|entity id|audience)\b)",
    re.IGNORECASE | re.DOTALL,
)
_NON_SAML_FIELD_TEXT = re.compile(r"\b(?:scim|swa)\b", re.IGNORECASE)
_EXPLICIT_ROUTE_NAMES = {
    "acs",
    "acsuri",
    "assertionconsumer",
    "assertionconsumerservice",
    "assertionconsumerurl",
    "audience",
    "audienceid",
    "audiencerestriction",
    "audienceuri",
    "auduri",
    "destination",
    "destinationurl",
    "entityid",
    "postbackurl",
    "recipient",
    "recipienturl",
    "serviceproviderid",
    "serviceproviderurl",
    "spentityid",
    "spid",
    "spurl",
    "ssourl",
}
_ROUTE_ORIGIN_NAMES = {
    "baseurl",
    "hosturl",
    "instanceurl",
    "rooturl",
    "siteurl",
}
_ROUTE_DISCRIMINATOR_NAME = re.compile(
    r"^(?:"
    r"(?:account|company|connection|customer|federation|instance|org|organization|"
    r"portal|site|tenant)(?:id|name|type)?|"
    r"(?:data(?:center|centre)|domain|environment|location|namespace|realm|region|"
    r"slug|subdomain)"
    r")$"
)
_SIGNAL_ORDER = (
    "explicit_route_input",
    "route_origin_input",
    "route_discriminator",
    "route_template_hint",
    "catalog_default_hint",
)


class SchemaAnalysisError(ValueError):
    """A catalog schema snapshot cannot be analyzed safely."""


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    parser = _TextExtractor()
    parser.feed(value)
    parser.close()
    cleaned = " ".join("".join(parser.parts).split())
    return cleaned or None


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, Mapping):
        string_items = (
            (key, item) for key, item in value.items() if isinstance(key, str)
        )
        return {key: _json_value(item) for key, item in sorted(string_items)}
    return None


def _route_signals(
    name: str,
    *,
    title: str | None,
    description: str | None,
    default: Any,
    has_default: bool,
) -> list[str]:
    compact_name = _compact(name)
    identity_text = " ".join(part for part in (name, title) if part)
    all_text = " ".join(part for part in (identity_text, description) if part)
    signals: set[str] = set()

    if (
        compact_name in _EXPLICIT_ROUTE_NAMES
        or re.fullmatch(r"(?:custom)?acs(?:url|uri)?\d*", compact_name)
        or _EXPLICIT_ROUTE_TEXT.search(identity_text)
    ):
        signals.add("explicit_route_input")

    if "explicit_route_input" not in signals and (
        compact_name.startswith(("scim", "swa"))
        or _NON_SAML_FIELD_TEXT.search(all_text)
    ):
        return []

    if compact_name in _ROUTE_ORIGIN_NAMES or _ROUTE_ORIGIN_TEXT.search(identity_text):
        signals.add("route_origin_input")

    if _ROUTE_DISCRIMINATOR_NAME.fullmatch(compact_name):
        signals.add("route_discriminator")

    if (
        "explicit_route_input" not in signals
        and description
        and _EXPLICIT_ROUTE_TEXT.search(description)
    ):
        signals.add("route_template_hint")

    default_text = ""
    if has_default and default is not None:
        default_text = str(default)
    if "explicit_route_input" in signals and (
        bool(description and _DEFAULT_ROUTE_HINT.search(description))
        or bool(default_text.strip())
    ):
        signals.add("catalog_default_hint")

    return [signal for signal in _SIGNAL_ORDER if signal in signals]


def _research_disposition(
    attributes: Sequence[Mapping[str, Any]], route_signals: set[str]
) -> str:
    if "catalog_default_hint" in route_signals:
        return "catalog_default_review"
    if any(
        attribute.get("required") is True
        and "explicit_route_input" in attribute.get("route_signals", [])
        for attribute in attributes
    ):
        return "required_explicit_route_review"
    if "explicit_route_input" in route_signals:
        return "optional_explicit_route_review"
    if route_signals & {
        "route_origin_input",
        "route_discriminator",
        "route_template_hint",
    }:
        return "route_template_research"
    return "targeted_research"


def _normalize_attribute(
    section_name: str,
    attribute_name: str,
    schema: Mapping[str, Any],
    *,
    section_required: set[str],
) -> dict[str, Any]:
    title = _clean_text(schema.get("title"))
    description = _clean_text(schema.get("description"))
    has_default = "default" in schema
    default = _json_value(schema.get("default"))
    enum = schema.get("enum")
    normalized_enum = (
        [_json_value(item) for item in enum] if isinstance(enum, list) else []
    )
    attribute_type = schema.get("type")
    if not isinstance(attribute_type, str):
        attribute_type = None
    attribute_format = schema.get("format")
    if not isinstance(attribute_format, str):
        attribute_format = None
    mutability = schema.get("mutability")
    if not isinstance(mutability, str):
        mutability = None
    scope = schema.get("scope")
    if not isinstance(scope, str):
        scope = None

    return {
        "section": section_name,
        "name": attribute_name,
        "title": title,
        "description": description,
        "type": attribute_type,
        "format": attribute_format,
        "required": (
            schema.get("required") is True or attribute_name in section_required
        ),
        "enum": normalized_enum,
        "has_default": has_default,
        "default": default if has_default else None,
        "mutability": mutability,
        "scope": scope,
        "route_signals": _route_signals(
            attribute_name,
            title=title,
            description=description,
            default=default,
            has_default=has_default,
        ),
    }


def _application_schema(application: Mapping[str, Any]) -> Mapping[str, Any] | None:
    embedded = application.get("_embedded")
    if not isinstance(embedded, Mapping):
        return None
    schema = embedded.get("schema")
    return schema if isinstance(schema, Mapping) else None


def _analyze_application(application: Mapping[str, Any]) -> dict[str, Any]:
    app_key = application.get("name")
    assert isinstance(app_key, str)
    diagnostics: list[str] = []
    attributes: list[dict[str, Any]] = []
    sensitive_count = 0
    required_sensitive_attribute_names: set[str] = set()
    schema = _application_schema(application)
    definitions = schema.get("definitions") if schema is not None else None

    if not isinstance(definitions, Mapping):
        diagnostics.append("missing_catalog_schema_definitions")
        definitions = {}

    for section_name, section in sorted(definitions.items()):
        if not isinstance(section_name, str) or not isinstance(section, Mapping):
            diagnostics.append(f"malformed_definition:{section_name}")
            continue
        raw_required = section.get("required")
        section_required = (
            {item for item in raw_required if isinstance(item, str)}
            if isinstance(raw_required, list)
            else set()
        )
        properties = section.get("properties")
        if properties is None:
            continue
        if not isinstance(properties, Mapping):
            diagnostics.append(f"malformed_properties:{section_name}")
            continue
        for attribute_name, attribute_schema in sorted(properties.items()):
            if not isinstance(attribute_name, str) or not isinstance(
                attribute_schema, Mapping
            ):
                diagnostics.append(
                    f"malformed_attribute:{section_name}.{attribute_name}"
                )
                continue
            if _SENSITIVE_ATTRIBUTE.search(attribute_name):
                sensitive_count += 1
                if (
                    attribute_schema.get("required") is True
                    or attribute_name in section_required
                ):
                    required_sensitive_attribute_names.add(attribute_name)
                continue
            attributes.append(
                _normalize_attribute(
                    section_name,
                    attribute_name,
                    attribute_schema,
                    section_required=section_required,
                )
            )

    route_signals = {
        signal for attribute in attributes for signal in attribute["route_signals"]
    }
    sign_on_modes = application.get("signOnModes")
    if not isinstance(sign_on_modes, list) or not all(
        isinstance(mode, str) for mode in sign_on_modes
    ):
        sign_on_modes = []

    return {
        "app_key": app_key,
        "display_name": application.get("displayName"),
        "sign_on_modes": sorted(sign_on_modes),
        "attribute_count": len(attributes),
        "omitted_sensitive_attribute_count": sensitive_count,
        "omitted_required_sensitive_attribute_names": sorted(
            required_sensitive_attribute_names
        ),
        "attributes": attributes,
        "diagnostics": sorted(diagnostics),
        "classification": {
            "route_signals": [
                signal for signal in _SIGNAL_ORDER if signal in route_signals
            ],
            "research_disposition": _research_disposition(attributes, route_signals),
            "authoritative_route": False,
            "requires_human_review": True,
        },
    }


def analyze_catalog_schema_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic, credential-filtered catalog attribute inventory."""
    applications = snapshot.get("applications")
    if not isinstance(applications, list):
        raise SchemaAnalysisError("schema snapshot applications must be a list")

    analyzed: list[dict[str, Any]] = []
    seen_app_keys: set[str] = set()
    for index, application in enumerate(applications):
        if not isinstance(application, Mapping):
            raise SchemaAnalysisError(f"application {index} must be an object")
        app_key = application.get("name")
        if not isinstance(app_key, str) or not _APP_KEY.fullmatch(app_key):
            raise SchemaAnalysisError(f"application {index} has an invalid app key")
        if app_key in seen_app_keys:
            raise SchemaAnalysisError(f"duplicate catalog application: {app_key}")
        seen_app_keys.add(app_key)
        analyzed.append(_analyze_application(application))
    analyzed.sort(key=lambda item: item["app_key"])

    signal_counts = {
        signal: sum(
            signal in application["classification"]["route_signals"]
            for application in analyzed
        )
        for signal in _SIGNAL_ORDER
    }
    return {
        "schema_version": SCHEMA_ANALYSIS_VERSION,
        "source_schema_version": snapshot.get("schema_version"),
        "source_captured_at": snapshot.get("captured_at"),
        "source": snapshot.get("source"),
        "analysis_scope": "catalog_schema_structure_only",
        "evidence_boundary": "research_candidates_not_authoritative_saml_routes",
        "requires_human_review": True,
        "application_count": len(analyzed),
        "attribute_count": sum(item["attribute_count"] for item in analyzed),
        "omitted_sensitive_attribute_count": sum(
            item["omitted_sensitive_attribute_count"] for item in analyzed
        ),
        "applications_with_diagnostics": sum(
            bool(item["diagnostics"]) for item in analyzed
        ),
        "applications_by_route_signal": signal_counts,
        "applications": analyzed,
    }
