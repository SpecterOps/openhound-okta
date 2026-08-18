from collections.abc import Callable, Mapping
from dataclasses import dataclass
from string import Formatter
from typing import Any

from .contract import OinRouteResolution, SamlRouteEvidence, route_resolution


ValueValidator = Callable[[Any], str | None]


@dataclass(frozen=True)
class RouteVariable:
    name: str
    app_field: str
    validator: ValueValidator
    diagnostic: str

    @property
    def source_field(self) -> str:
        return f"settings.app.{self.app_field}"


@dataclass(frozen=True)
class RouteTemplate:
    acs: str
    sp_entity: str
    acs_variables: tuple[str, ...]
    sp_entity_variables: tuple[str, ...]
    acs_static_source: str | None = None
    sp_entity_static_source: str | None = None
    index: int | None = 0
    binding: str | None = None
    is_default: bool | None = True


@dataclass(frozen=True)
class RouteProfile:
    profile_id: str
    app_keys: tuple[str, ...]
    variables: tuple[RouteVariable, ...]
    routes: tuple[RouteTemplate, ...]
    target_product_family: str
    route_source: str
    extraction_mode: str
    evidence_references: tuple[str, ...]
    evidence_reviewed_at: str

    @property
    def app_fields(self) -> tuple[str, ...]:
        return tuple(variable.app_field for variable in self.variables)

    def __post_init__(self) -> None:
        if not self.profile_id or not self.app_keys or not self.routes:
            raise ValueError("OIN route profiles require an ID, app key, and route")
        if len(set(self.app_keys)) != len(self.app_keys):
            raise ValueError(f"duplicate app key within OIN profile {self.profile_id}")
        if not self.evidence_references or not self.evidence_reviewed_at:
            raise ValueError(f"OIN profile {self.profile_id} lacks evidence metadata")

        variable_names = {variable.name for variable in self.variables}
        if len(variable_names) != len(self.variables):
            raise ValueError(f"duplicate variable within OIN profile {self.profile_id}")
        referenced_variables: set[str] = set()
        for route in self.routes:
            for field_name, template, source_variables, static_source in (
                (
                    "ACS",
                    route.acs,
                    route.acs_variables,
                    route.acs_static_source,
                ),
                (
                    "SP entity",
                    route.sp_entity,
                    route.sp_entity_variables,
                    route.sp_entity_static_source,
                ),
            ):
                placeholders = {
                    placeholder
                    for _, placeholder, _, _ in Formatter().parse(template)
                    if placeholder
                }
                source_variable_set = set(source_variables)
                unknown = (placeholders | source_variable_set) - variable_names
                if unknown:
                    raise ValueError(
                        f"OIN profile {self.profile_id} references unknown variables: "
                        f"{', '.join(sorted(unknown))}"
                    )
                if placeholders != source_variable_set:
                    raise ValueError(
                        f"OIN profile {self.profile_id} {field_name} provenance "
                        "does not match its template variables"
                    )
                if bool(placeholders) == bool(static_source):
                    raise ValueError(
                        f"OIN profile {self.profile_id} {field_name} must use "
                        "either instance variables or a documented static source"
                    )
                referenced_variables.update(placeholders)
        if referenced_variables != variable_names:
            raise ValueError(f"OIN profile {self.profile_id} has unused variables")

    def resolve(self, app_settings: Mapping[str, Any]) -> OinRouteResolution:
        values: dict[str, str] = {}
        diagnostics: list[str] = []
        variables_by_name = {variable.name: variable for variable in self.variables}
        for variable in self.variables:
            value = variable.validator(app_settings.get(variable.app_field))
            if value is None:
                diagnostics.append(variable.diagnostic)
            else:
                values[variable.name] = value
        if diagnostics:
            return route_resolution(diagnostics=diagnostics)

        routes = [
            SamlRouteEvidence(
                acs_url=route.acs.format_map(values),
                sp_entity_id=route.sp_entity.format_map(values),
                index=route.index,
                binding=route.binding,
                is_default=route.is_default,
                target_product_family=self.target_product_family,
                route_source=self.route_source,
                extraction_mode=self.extraction_mode,
                acs_source_field="+".join(
                    variables_by_name[name].source_field for name in route.acs_variables
                )
                or route.acs_static_source
                or "",
                sp_entity_source_field=(
                    "+".join(
                        variables_by_name[name].source_field
                        for name in route.sp_entity_variables
                    )
                    or route.sp_entity_static_source
                    or ""
                ),
            )
            for route in self.routes
        ]
        return route_resolution(routes=routes)
