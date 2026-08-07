from openhound_okta.kinds import edges as ek
from openhound_okta.models import CustomRole


class StubLookup:
    def org_id(self):
        return "org-1"

    def custom_role_permissions(self, role_id: str):
        assert role_id == "custom-role-1"
        return (
            "okta.users.credentials.resetPassword",
            "okta.users.credentials.manage",
        )


def make_role() -> CustomRole:
    role = CustomRole.model_validate(
        {
            "id": "custom-role-1",
            "label": "Password Reset Operator",
            "description": "Can reset passwords",
            "created": "2026-01-01T00:00:00Z",
            "lastUpdated": "2026-01-02T00:00:00Z",
        }
    )
    role._lookup = StubLookup()
    role._extras = {"tenant": "example.okta.com"}
    return role


def test_custom_role_node_emits_oktahound_equivalent_properties():
    role = make_role()

    properties = role.as_node.properties

    assert properties.id == "custom-role-1"
    assert properties.name == "PASSWORD RESET OPERATOR"
    assert properties.displayname == "Password Reset Operator"
    assert properties.okta_domain == "example.okta.com"
    assert properties.permissions == [
        "okta.users.credentials.resetPassword",
        "okta.users.credentials.manage",
    ]
    assert not hasattr(properties, "label")
    assert not hasattr(properties, "description")


def test_custom_role_contains_edge_uses_role_id():
    role = make_role()

    edge = next(role.edges)

    assert edge.kind == ek.CONTAINS
    assert edge.end.value == "CUSTOM-ROLE-1"
