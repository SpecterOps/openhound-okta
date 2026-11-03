"""Identity-provider and SAML federation collection."""

import logging
from typing import Any
from xml.etree.ElementTree import Element

import requests
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from dlt.extract.resource import DltResource

from openhound_okta.main import app
from openhound_okta.models import (
    Application,
    IdentityProvider,
    IDPUser,
    SamlAccountResolutionField,
    SamlAccountResolutionRule,
    SamlAssertionConsumerService,
    SamlClaimMapping,
    SamlFederationProvider,
    SamlIssuer,
    SamlServiceProvider,
    SamlServiceProviderAssertionConsumerService,
    SamlTrustedIssuer,
)
from openhound_okta.models.saml import (
    saml_account_resolution_field_row,
    saml_account_resolution_rule_row,
    saml_acs_rows,
    saml_claim_mapping_rows,
    saml_federation_provider_row,
    saml_issuer_row,
    saml_service_provider_row,
    saml_sp_acs_rows,
    saml_trusted_issuer_row,
)
from openhound_okta.source_context import SourceContext
from openhound_okta.utils.http import OktaRetryExhaustedError

logger = logging.getLogger(__name__)


def _saml_metadata_fields(
    ctx: SourceContext, application: dict[str, Any]
) -> dict[str, str]:
    metadata_link = (application.get("_links") or {}).get("metadata") or {}
    if not metadata_link.get("href"):
        return {}

    app_id = application.get("id")
    if not app_id:
        return {}

    root = _saml_metadata_root(
        ctx,
        f"/api/v1/apps/{app_id}/sso/saml/metadata",
        "app",
        app_id,
    )
    if root is None:
        return {}

    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    sso_url = None
    for node in root.findall(".//md:SingleSignOnService", namespace):
        location = node.attrib.get("Location")
        binding = node.attrib.get("Binding")
        # Prefer the HTTP-POST SSO endpoint when metadata exposes multiple bindings.
        if location and (
            sso_url is None
            or binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ):
            sso_url = location

    result = {}
    if root.attrib.get("entityID"):
        result["saml_metadata_entity_id"] = root.attrib["entityID"]
    if sso_url:
        result["saml_metadata_sso_url"] = sso_url
    return result


def _saml_metadata_root(
    ctx: SourceContext,
    path: str,
    object_kind: str,
    object_id: str,
) -> Element | None:
    try:
        response = ctx.pool.get_saml_metadata(path)
        return ET.fromstring(response.content)
    except OktaRetryExhaustedError:
        logger.error(
            "Required SAML metadata request exhausted retries for Okta %s %s",
            object_kind,
            object_id,
            exc_info=True,
        )
        raise
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code not in {403, 404}:
            raise
        logger.warning(
            "SAML metadata is unavailable for Okta %s %s status=%s",
            object_kind,
            object_id,
            status_code,
        )
        return None
    except (ET.ParseError, DefusedXmlException):
        logger.warning(
            "Okta returned invalid SAML metadata XML for %s %s",
            object_kind,
            object_id,
            exc_info=True,
        )
        return None


def _saml_idp_metadata_fields(
    ctx: SourceContext,
    identity_provider: dict[str, Any],
) -> dict[str, Any]:
    metadata_link = (identity_provider.get("_links") or {}).get("metadata") or {}
    idp_id = identity_provider.get("id")
    if not metadata_link.get("href") or not idp_id:
        return {}

    root = _saml_metadata_root(
        ctx,
        f"/api/v1/idps/{idp_id}/metadata.xml",
        "identity provider",
        idp_id,
    )
    if root is None:
        return {}

    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    endpoints = []
    for node in root.findall(
        ".//md:SPSSODescriptor/md:AssertionConsumerService",
        namespace,
    ):
        location = node.attrib.get("Location")
        if not location:
            continue
        raw_index = node.attrib.get("index")
        try:
            index = int(raw_index) if raw_index is not None else None
        except ValueError:
            index = None
        raw_default = node.attrib.get("isDefault")
        endpoints.append(
            {
                "url": location,
                "binding": node.attrib.get("Binding"),
                "index": index,
                "is_default": (
                    raw_default.casefold() == "true"
                    if raw_default is not None
                    else None
                ),
            }
        )

    result: dict[str, Any] = {}
    if root.attrib.get("entityID"):
        result["saml_metadata_entity_id"] = root.attrib["entityID"]
    if endpoints:
        result["saml_metadata_acs_endpoints"] = endpoints
    return result


@app.transformer(
    name="saml_federation_providers",
    columns=SamlFederationProvider,
    parallelized=True,
)
def saml_federation_providers(application: Application):
    # Keep SAML row builders pure; DLT transformer boundaries recompute by design.
    row = saml_federation_provider_row(application)
    if row:
        yield row


@app.transformer(name="saml_issuers", columns=SamlIssuer, parallelized=True)
def saml_issuers(application: Application):
    row = saml_issuer_row(application)
    if row:
        yield row


@app.transformer(
    name="saml_assertion_consumer_services",
    columns=SamlAssertionConsumerService,
    parallelized=True,
)
def saml_assertion_consumer_services(application: Application):
    yield from saml_acs_rows(application)


@app.transformer(
    name="saml_claim_mappings", columns=SamlClaimMapping, parallelized=True
)
def saml_claim_mappings(application: Application):
    yield from saml_claim_mapping_rows(application)


@app.transformer(
    name="saml_service_providers",
    columns=SamlServiceProvider,
    parallelized=True,
)
def saml_service_providers(identity_provider: IdentityProvider, ctx: SourceContext):
    row = saml_service_provider_row(identity_provider, ctx.tenant_domain)
    if row:
        yield row


@app.transformer(
    name="saml_account_resolution_rules",
    columns=SamlAccountResolutionRule,
    parallelized=True,
)
def saml_account_resolution_rules(identity_provider: IdentityProvider):
    row = saml_account_resolution_rule_row(identity_provider)
    if row:
        yield row


@app.transformer(
    name="saml_account_resolution_fields",
    columns=SamlAccountResolutionField,
    parallelized=True,
)
def saml_account_resolution_fields(identity_provider: IdentityProvider):
    row = saml_account_resolution_field_row(identity_provider)
    if row:
        yield row


@app.transformer(
    name="saml_trusted_issuers", columns=SamlTrustedIssuer, parallelized=True
)
def saml_trusted_issuers(identity_provider: IdentityProvider, ctx: SourceContext):
    row = saml_trusted_issuer_row(identity_provider, ctx.tenant_domain)
    if row:
        yield row


@app.transformer(
    name="saml_sp_assertion_consumer_services",
    columns=SamlServiceProviderAssertionConsumerService,
    parallelized=True,
)
def saml_sp_assertion_consumer_services(identity_provider: IdentityProvider):
    yield from saml_sp_acs_rows(identity_provider)


@app.resource(name="identity_providers", columns=IdentityProvider, parallelized=True)
def identity_providers(ctx: SourceContext):
    """DLT resource, fetches Okta identity providers via GET /api/v1/idps.

    Yields:
        identity_provider (IdentityProvider): Identity provider records.
    """
    for page in ctx.pool.paginate("/api/v1/idps"):
        for item in page:
            protocol = item.get("protocol") or {}
            if item.get("type") == "SAML2" and protocol.get("type") == "SAML2":
                item = {**item, **_saml_idp_metadata_fields(ctx, item)}
            yield _redact_idp_client_secret(item)


def _redact_idp_client_secret(item: dict[str, Any]) -> dict[str, Any]:
    # Okta returns the plaintext client_secret of OIDC and social identity
    # providers under protocol.credentials.client; only client_id is modeled.
    protocol = item.get("protocol")
    if not isinstance(protocol, dict):
        return item
    credentials = protocol.get("credentials")
    if not isinstance(credentials, dict):
        return item
    client = credentials.get("client")
    if not isinstance(client, dict) or "client_secret" not in client:
        return item
    return {
        **item,
        "protocol": {
            **protocol,
            "credentials": {
                **credentials,
                "client": {k: v for k, v in client.items() if k != "client_secret"},
            },
        },
    }


@app.transformer(name="identity_provider_users", columns=IDPUser, parallelized=True)
def identity_provider_users(idp: IdentityProvider, ctx: SourceContext):
    for page in ctx.pool.paginate(
        f"/api/v1/idps/{idp.id}/users",
        params={"limit": ctx.identity_provider_users_page_size},
    ):
        for item in page:
            subject = (idp.policy.subject or {}) if idp.policy else {}
            user_name_template = subject.get("userNameTemplate") or {}
            yield {
                "idp_id": idp.id,
                "idp_name": idp.name,
                "idp_type": idp.type,
                "idp_protocol_type": getattr(
                    getattr(idp, "protocol", None),
                    "type",
                    None,
                ),
                "idp_status": idp.status,
                "idp_url": idp.idp_url,
                "idp_subject_user_name_template": user_name_template.get("template"),
                "idp_subject_match_type": subject.get("matchType"),
                "idp_subject_filter": subject.get("filter"),
                **item,
            }


def all_resources(
    applications_resource: DltResource, ctx: SourceContext
) -> tuple[DltResource, ...]:
    """Compose federation pipelines using the shared application inventory."""
    identity_providers_resource = identity_providers(ctx)
    return (
        applications_resource | saml_federation_providers(),
        applications_resource | saml_issuers(),
        applications_resource | saml_assertion_consumer_services(),
        applications_resource | saml_claim_mappings(),
        identity_providers_resource,
        identity_providers_resource | saml_service_providers(ctx),
        identity_providers_resource | saml_account_resolution_rules(),
        identity_providers_resource | saml_account_resolution_fields(),
        identity_providers_resource | saml_trusted_issuers(ctx),
        identity_providers_resource | saml_sp_assertion_consumer_services(),
        identity_providers_resource | identity_provider_users(ctx),
    )
