from collections.abc import Iterator

from openhound.core.models.entries_dataclass import Edge, EdgePath

from openhound_okta.kinds import edges as ek


DIRECT_ASSIGNMENT_TYPES = {
    "user": "USER",
    "group": "GROUP",
    "client": "CLIENT",
}

ADD_MEMBER_PERMISSIONS = (
    "okta.groups.manage",
    "okta.groups.members.manage",
)


def add_member_edges(role_assignment) -> Iterator[Edge]:
    expected_assignment_type = DIRECT_ASSIGNMENT_TYPES.get(role_assignment.from_resource)

    if (
        role_assignment.type != "CUSTOM"
        or not role_assignment.role
        or role_assignment.status != "ACTIVE"
        or role_assignment.assignment_type != expected_assignment_type
        or not role_assignment.resource_set
    ):
        return

    has_permission = any(
        role_assignment._lookup.has_role_permission(role_assignment.role, permission)
        for permission in ADD_MEMBER_PERMISSIONS
    )
    if not has_permission:
        return

    for group_id in role_assignment._lookup.resource_set_non_admin_group_ids(
        role_assignment.resource_set
    ):
        yield Edge(
            kind=ek.ADD_MEMBER,
            start=EdgePath(value=role_assignment.source_id, match_by="id"),
            end=EdgePath(value=group_id, match_by="id"),
        )
