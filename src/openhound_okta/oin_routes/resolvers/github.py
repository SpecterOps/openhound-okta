from collections.abc import Mapping
from typing import Any

from ..contract import (
    CallableRouteProvider,
    OinRouteResolution,
    SamlRouteEvidence,
    route_resolution,
)
from ..validators import github_slug


def _github_organization_route(
    app_settings: Mapping[str, Any],
) -> OinRouteResolution:
    org_field = "githubOrg" if app_settings.get("githubOrg") else "orgName"
    org_name = github_slug(app_settings.get(org_field))
    if not org_name:
        return route_resolution(
            diagnostics=("missing_or_malformed_settings.app.githubOrg_or_orgName",)
        )
    source_field = f"settings.app.{org_field}"
    return route_resolution(
        routes=(
            SamlRouteEvidence(
                acs_url=f"https://github.com/orgs/{org_name}/saml/consume",
                sp_entity_id=f"https://github.com/orgs/{org_name}",
                index=0,
                binding=None,
                is_default=True,
                target_product_family="github_organization",
                route_source="settings.app+documented_github_route",
                extraction_mode="allowlisted_deterministic_route",
                acs_source_field=source_field,
                sp_entity_source_field=source_field,
            ),
        )
    )


GITHUB_ORGANIZATION_PROVIDER = CallableRouteProvider(
    profile_id="github_organization",
    app_keys=("githubcloud",),
    app_fields=("githubOrg", "orgName"),
    resolver=_github_organization_route,
    evidence_references=("openhound_saml:os-0bef",),
    evidence_reviewed_at="2026-07-13",
)
