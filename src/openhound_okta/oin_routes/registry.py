from collections.abc import Iterable, Mapping
from datetime import date
from typing import Any

from .catalog import OIN_ROUTE_PROFILES
from .contract import OinRouteProvider, OinRouteResolution
from .resolvers import CUSTOM_ROUTE_PROVIDERS


def build_registry(
    providers: Iterable[OinRouteProvider],
) -> dict[str, OinRouteProvider]:
    registry: dict[str, OinRouteProvider] = {}
    profile_ids: set[str] = set()
    for provider in providers:
        if provider.profile_id in profile_ids:
            raise ValueError(f"duplicate OIN route profile ID: {provider.profile_id}")
        profile_ids.add(provider.profile_id)
        if not provider.evidence_references:
            raise ValueError(
                f"OIN route profile {provider.profile_id} lacks evidence references"
            )
        try:
            date.fromisoformat(provider.evidence_reviewed_at)
        except ValueError as error:
            raise ValueError(
                f"OIN route profile {provider.profile_id} has an invalid review date"
            ) from error
        for app_key in provider.app_keys:
            if not app_key:
                raise ValueError(
                    f"OIN route profile {provider.profile_id} has an empty app key"
                )
            if app_key in registry:
                raise ValueError(f"duplicate OIN route app key: {app_key}")
            registry[app_key] = provider
    return registry


OIN_ROUTE_PROVIDERS: tuple[OinRouteProvider, ...] = (
    *OIN_ROUTE_PROFILES,
    *CUSTOM_ROUTE_PROVIDERS,
)
OIN_ROUTE_REGISTRY = build_registry(OIN_ROUTE_PROVIDERS)


def resolve_oin_routes(
    app_name: Any,
    app_settings: Mapping[str, Any],
) -> OinRouteResolution:
    provider = OIN_ROUTE_REGISTRY.get(app_name) if isinstance(app_name, str) else None
    return provider.resolve(app_settings) if provider else OinRouteResolution()
