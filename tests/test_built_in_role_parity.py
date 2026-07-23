from openhound_okta.kinds import edges as ek
from openhound_okta.models import BuiltInRole
from openhound_okta.models.built_in_role import (
    BUILT_IN_ROLES,
    built_in_role_graph_id,
)


class StubLookup:
    def org_id(self):
        return "org-1"


def make_role(role_type: str) -> BuiltInRole:
    role = BuiltInRole.model_validate({"type": role_type})
    role._lookup = StubLookup()
    role._extras = {"tenant": "example.okta.com"}
    return role


def test_built_in_roles_match_oktahound_supported_role_set():
    assert BUILT_IN_ROLES == (
        "API_ACCESS_MANAGEMENT_ADMIN",
        "APP_ADMIN",
        "GROUP_MEMBERSHIP_ADMIN",
        "HELP_DESK_ADMIN",
        "MOBILE_ADMIN",
        "ORG_ADMIN",
        "READ_ONLY_ADMIN",
        "REPORT_ADMIN",
        "SUPER_ADMIN",
        "USER_ADMIN",
        "WORKFLOWS_ADMIN",
    )


def test_built_in_role_node_emits_oktahound_equivalent_properties():
    role = make_role("APP_ADMIN")

    properties = role.as_node.properties

    assert properties.id == "APP_ADMIN@example.okta.com"
    assert properties.name == "Application Administrator"
    assert properties.displayname == "Application Administrator"
    assert properties.okta_domain == "example.okta.com"
    assert "okta.apps.manage" in properties.permissions
    assert not hasattr(properties, "is_built_in")


def test_built_in_role_node_emits_workflows_description():
    role = make_role("WORKFLOWS_ADMIN")

    assert role.as_node.properties.description == "An admin role for managing workflows"


def test_built_in_role_contains_edge_uses_domain_qualified_id():
    role = make_role("SUPER_ADMIN")

    edge = next(role.edges)

    assert edge.kind == ek.CONTAINS
    assert edge.end.value == built_in_role_graph_id("SUPER_ADMIN", "example.okta.com")
