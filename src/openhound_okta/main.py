from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import dlt
from dlt.common.configuration import inject_section, resolve_configuration
from dlt.extract.pipe_iterator import PipeIterator
from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext

from openhound_okta.lookup import OktaLookup
from openhound_okta.telemetry import TelemetrySettings, build_telemetry
from openhound_okta.transforms import transforms

app = OpenHound("okta", source_kind="Okta", help="OpenGraph collector for Okta")

_TELEMETRY_CONFIG_PREFIX = "sources.source.okta.telemetry"


def _telemetry_settings_from_config() -> TelemetrySettings:
    fields: tuple[tuple[str, type[Any]], ...] = (
        ("enabled", bool),
        ("output_directory", str),
        ("reporting_interval_seconds", float),
        ("max_file_bytes", int),
        ("max_interval_records", int),
        ("queue_capacity", int),
    )
    values = {
        name: value
        for name, expected_type in fields
        if (
            value := dlt.config.get(
                f"{_TELEMETRY_CONFIG_PREFIX}.{name}", expected_type
            )
        )
        is not None
    }
    return TelemetrySettings.from_mapping(values)


def _extract_performance_settings_from_source(
    source: DltSource,
) -> dict[str, int]:
    # DLT resolves PipeIteratorConfiguration inside this source context. Reuse
    # the same spec and context so scoped overrides and defaults cannot drift
    # from the values used to construct DLT's worker pool.
    with inject_section(source._get_config_section_context()):
        config = resolve_configuration(PipeIterator.PipeIteratorConfiguration())
    return {
        "extract_workers": config.workers,
        "extract_max_parallel_items": config.max_parallel_items,
    }


def _tenant_domain_from_config() -> str:
    # DLT resolves source environment variables under sources.okta, while existing
    # secrets.toml bundles use sources.source.okta. Check both so a missing value
    # cannot become b"" and leak DLT's U+F02B bytes marker into tenant_domain.
    tenant_url: str | None = dlt.secrets.get(
        "sources.okta.credentials.base_url"
    ) or dlt.secrets.get("sources.source.okta.credentials.base_url")
    if not isinstance(tenant_url, str) or not tenant_url.strip():
        raise ValueError("Okta base URL is unavailable during conversion")

    try:
        parsed = urlparse(tenant_url.strip())
        _ = parsed.port
        tenant_domain = parsed.hostname
    except ValueError as error:
        raise ValueError(
            "Okta base URL must include a URL scheme and hostname"
        ) from error
    if not parsed.scheme or not tenant_domain:
        raise ValueError("Okta base URL must include a URL scheme and hostname")
    return tenant_domain.casefold()


@app.collect()
def collect(ctx: CollectContext) -> DltSource:
    """Register a Typer CLI command that collects Okta resources and stores them (filtered) on disk.

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    telemetry = build_telemetry(
        _telemetry_settings_from_config(),
        collection_output=Path(ctx.pipeline.output_path),
    )
    try:
        source_method = okta_source(telemetry=telemetry)
        telemetry.set_effective_settings(
            _extract_performance_settings_from_source(source_method)
        )
    except BaseException as error:
        telemetry.finish("incomplete", error)
        raise

    original_run = ctx.pipeline.run

    def run_with_telemetry(source_object: DltSource, **kwargs):
        try:
            result = original_run(source_object, **kwargs)
        except BaseException as error:
            telemetry.finish("incomplete", error)
            raise
        telemetry.finish("complete")
        return result

    ctx.pipeline.run = run_with_telemetry
    return source_method


@app.convert(lookup=OktaLookup)
def convert(ctx: ConvertContext):
    """Register a Typer CLI command that converts previously collected Okta resources into OpenGraph nodes and edges.

    Args:
        ctx (ConvertContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    tenant_domain = _tenant_domain_from_config()
    if ctx.lookup:
        ctx.lookup.tenant_domain = tenant_domain
    return okta_source(), {"tenant": tenant_domain}


def preprocessing_resources() -> dict[str, str]:
    """Map collected Okta resources into their preprocessing tables."""
    return {
        "organization": "organization",
        "users": "users",
        "user_factors": "user_factors",
        "groups": "groups",
        "group_memberships": "group_memberships",
        "group_assigned_apps": "group_assigned_apps",
        "applications": "applications",
        "application_grants": "application_grants",
        "application_users": "application_users",
        "api_services": "api_services",
        "saml_federation_providers": "saml_federation_providers",
        "saml_issuers": "saml_issuers",
        "saml_assertion_consumer_services": "saml_assertion_consumer_services",
        "saml_claim_mappings": "saml_claim_mappings",
        "saml_service_providers": "saml_service_providers",
        "saml_account_resolution_rules": "saml_account_resolution_rules",
        "saml_account_resolution_fields": "saml_account_resolution_fields",
        "saml_trusted_issuers": "saml_trusted_issuers",
        "saml_sp_assertion_consumer_services": "saml_sp_assertion_consumer_services",
        "application_secrets": "application_secrets",
        "api_service_secrets": "api_service_secrets",
        "devices": "devices",
        "authorization_servers": "authorization_servers",
        "identity_providers": "identity_providers",
        "identity_provider_users": "identity_provider_users",
        "policies": "policies",
        "resources": "resources",
        "resource_set_role_assignments": "resource_set_role_assignments",
        "privileged_users": "privileged_users",
        "user_role_assignments": "user_role_assignments",
        "group_role_assignments": "group_role_assignments",
        "client_role_assignments": "client_role_assignments",
        "custom_role_permissions": "custom_role_permissions",
    }


@app.preproc(transformer=transforms)
def preprocess(ctx: PreProcContext):
    return preprocessing_resources()
