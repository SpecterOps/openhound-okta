from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class SamlRouteEvidence:
    acs_url: str
    sp_entity_id: str
    index: int | None
    binding: str | None
    is_default: bool | None
    target_product_family: str
    route_source: str
    extraction_mode: str
    acs_source_field: str
    sp_entity_source_field: str
    route_conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class OinRouteResolution:
    routes: tuple[SamlRouteEvidence, ...] = ()
    diagnostics: tuple[str, ...] = ()


class OinRouteProvider(Protocol):
    @property
    def profile_id(self) -> str: ...

    @property
    def app_keys(self) -> tuple[str, ...]: ...

    @property
    def app_fields(self) -> tuple[str, ...]: ...

    @property
    def evidence_references(self) -> tuple[str, ...]: ...

    @property
    def evidence_reviewed_at(self) -> str: ...

    def resolve(self, app_settings: Mapping[str, Any]) -> OinRouteResolution: ...


OinRouteResolver = Callable[[Mapping[str, Any]], OinRouteResolution]


@dataclass(frozen=True)
class CallableRouteProvider:
    profile_id: str
    app_keys: tuple[str, ...]
    app_fields: tuple[str, ...]
    resolver: OinRouteResolver
    evidence_references: tuple[str, ...]
    evidence_reviewed_at: str

    def resolve(self, app_settings: Mapping[str, Any]) -> OinRouteResolution:
        return self.resolver(app_settings)


def route_resolution(
    routes: Sequence[SamlRouteEvidence] = (),
    diagnostics: Sequence[str] = (),
) -> OinRouteResolution:
    """Create a stable resolution while deduplicating identical route tuples."""
    unique_routes: list[SamlRouteEvidence] = []
    route_keys: set[tuple[str, str, int | None, str | None, bool | None]] = set()
    for route in routes:
        key = (
            route.acs_url,
            route.sp_entity_id,
            route.index,
            route.binding,
            route.is_default,
        )
        if key not in route_keys:
            route_keys.add(key)
            unique_routes.append(route)
    return OinRouteResolution(
        routes=tuple(unique_routes),
        diagnostics=tuple(dict.fromkeys(diagnostics)),
    )
