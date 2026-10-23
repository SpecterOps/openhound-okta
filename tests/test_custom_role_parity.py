from datetime import UTC, datetime

from openhound_okta.kinds import edges as ek
from openhound_okta.models import CustomRole, CustomRolePermission


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


def test_custom_role_timestamps_parse_as_datetimes():
    role = make_role()

    assert role.created == datetime(2026, 1, 1, tzinfo=UTC)
    assert role.last_updated == datetime(2026, 1, 2, tzinfo=UTC)


def test_custom_role_permission_timestamps_parse_as_datetimes():
    # Shape of GET /api/v1/iam/roles/{roleId}/permissions items as returned by Okta.
    permission = CustomRolePermission.model_validate(
        {
            "label": "okta.agents.manage",
            "created": "2025-10-20T13:16:02.000Z",
            "lastUpdated": "2025-10-20T13:16:02.000Z",
            "conditions": None,
            "_links": {
                "role": {
                    "href": "https://example.okta.com/api/v1/iam/roles/cr0wl72zcmxDVUHgw697"
                },
                "self": {
                    "href": "https://example.okta.com/api/v1/iam/roles/cr0wl72zcmxDVUHgw697/permissions/okta.agents.manage"
                },
            },
            "role_id": "cr0wl72zcmxDVUHgw697",
            "role_label": "Agent Operator",
        }
    )

    expected = datetime(2025, 10, 20, 13, 16, 2, tzinfo=UTC)
    assert permission.created == expected
    assert permission.last_updated == expected
    assert permission.conditions is None
    assert permission.links == {
        "role": {
            "href": "https://example.okta.com/api/v1/iam/roles/cr0wl72zcmxDVUHgw697"
        },
        "self": {
            "href": "https://example.okta.com/api/v1/iam/roles/cr0wl72zcmxDVUHgw697/permissions/okta.agents.manage"
        },
    }
