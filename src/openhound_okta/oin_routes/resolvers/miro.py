from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from ..contract import (
    CallableRouteProvider,
    OinRouteResolution,
    SamlRouteEvidence,
    route_resolution,
)
from ..validators import https_url


_DEFAULT_ACS_URL = "https://miro.com/sso/saml"
_DEFAULT_SP_ENTITY_ID = "https://miro.com/"


def _miro_url(value: Any) -> str | None:
    url = https_url(value)
    if url is None:
        return None
    hostname = urlsplit(url).hostname
    if hostname is None or (
        hostname != "miro.com" and not hostname.endswith(".miro.com")
    ):
        return None
    return url


def _miro_route(app_settings: Mapping[str, Any]) -> OinRouteResolution:
    has_acs_field = "customAcsUrl" in app_settings
    has_sp_entity_field = "customEntityId" in app_settings
    raw_acs_url = app_settings.get("customAcsUrl")
    raw_sp_entity_id = app_settings.get("customEntityId")
    if (
        has_acs_field
        and has_sp_entity_field
        and raw_acs_url is None
        and raw_sp_entity_id is None
    ):
        return route_resolution(
            routes=(
                SamlRouteEvidence(
                    acs_url=_DEFAULT_ACS_URL,
                    sp_entity_id=_DEFAULT_SP_ENTITY_ID,
                    index=0,
                    binding=None,
                    is_default=True,
                    target_product_family="miro",
                    route_source="documented_miro_default_route",
                    extraction_mode="allowlisted_static_default_route",
                    acs_source_field="documented_static_miro_acs",
                    sp_entity_source_field="documented_static_miro_sp_entity",
                ),
            )
        )

    acs_url = _miro_url(raw_acs_url)
    sp_entity_id = _miro_url(raw_sp_entity_id)
    diagnostics: list[str] = []
    if acs_url is None:
        diagnostics.append("missing_or_malformed_settings.app.customAcsUrl")
    if sp_entity_id is None:
        diagnostics.append("missing_or_malformed_settings.app.customEntityId")
    if diagnostics:
        return route_resolution(diagnostics=diagnostics)
    assert acs_url is not None and sp_entity_id is not None

    return route_resolution(
        routes=(
            SamlRouteEvidence(
                acs_url=acs_url,
                sp_entity_id=sp_entity_id,
                index=0,
                binding=None,
                is_default=True,
                target_product_family="miro",
                route_source="settings.app",
                extraction_mode="oin_explicit_fields",
                acs_source_field="settings.app.customAcsUrl",
                sp_entity_source_field="settings.app.customEntityId",
            ),
        )
    )


MIRO_PROVIDER = CallableRouteProvider(
    profile_id="miro",
    app_keys=("realtime_board",),
    app_fields=("customAcsUrl", "customEntityId"),
    resolver=_miro_route,
    evidence_references=(
        "https://help.miro.com/hc/en-us/articles/360017571414-Single-sign-on-SSO",
        "https://help.miro.com/hc/en-us/articles/360023901054-How-to-configure-OKTA-SSO",
    ),
    evidence_reviewed_at="2026-08-14",
)
