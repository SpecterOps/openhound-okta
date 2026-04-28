from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.read_client_secret import read_client_secret_edges


@dataclass
class GroupRoleAssignmentProperties(OktaNodeProperties):
    id: str
    assignment_type: str
    type: str
    status: str
    created: datetime | None = None
    last_updated: datetime | None = None


class App(BaseModel):
    name: str
    id: str | None = None  # Seem to be optional
    display_name: str = Field(alias="displayName")
    status: str
    category: str


class Group(BaseModel):
    id: str
    type: str
    object_class: list[str] = Field(alias="objectClass")


class Catalog(BaseModel):
    apps: list[App] | None = None


class Target(BaseModel):
    catalog: Catalog | None = None
    groups: list[Group] | None = None


class Embedded(BaseModel):
    targets: Target | None = None


@app.asset(
    description="Okta group role assignment",
    node=NodeDef(
        icon="clipboard-check",
        kind=nk.ROLE_ASSIGNMENT,
        description="Okta group role assignment node",
        properties=GroupRoleAssignmentProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.GROUP,
            end=nk.ROLE_ASSIGNMENT,
            kind=ek.HAS_ROLE_ASSIGNMENT,
            description="Group has a role assignment",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.ROLE,
            kind=ek.HAS_ROLE,
            description="Group is assigned a built-in role",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.CUSTOM_ROLE,
            kind=ek.HAS_ROLE,
            description="Group is assigned a custom role",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="Group can add member to groups",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Group has group admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="Group has group admin role for groups",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.APPLICATION,
            kind=ek.APP_ADMIN,
            description="Group has app admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.CLIENT_SECRET,
            kind=ek.READ_CLIENT_SECRET,
            description="Group can read application client secrets",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.GROUP_MEMBERSHIP_ADMIN,
            description="Group has GROUP_MEMBERSHIP_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.HELPDESK_ADMIN,
            description="Group has HELPDESK_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.DEVICE,
            kind=ek.MOBILE_ADMIN,
            description="Group has MOBILE_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.ORG_ADMIN,
            description="Group has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.ORG_ADMIN,
            description="Group has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.DEVICE,
            kind=ek.ORG_ADMIN,
            description="Group has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.ORG,
            kind=ek.SUPER_ADMIN,
            description="Group has SUPER_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="Group has GROUP_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Group has GROUP_ADMIN role",
            traversable=True,
        ),
        # Scoped to
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to group",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.ORG,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to org",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.APPLICATION,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to application",
            traversable=False,
        ),
    ],
)
class GroupRoleAssignment(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    from_resource: str
    source_id: str

    assignment_type: str = Field(alias="assignmentType")
    resource_set: str | None = Field(alias="resource-set", default=None)
    status: str
    created: datetime | None
    name: str | None = None
    label: str
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)
    features: list[str] = Field(default_factory=list)
    type: str
    role: str | None = None
    embedded: Embedded | None = Field(alias="_embedded", default=None)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.ROLE_ASSIGNMENT],
            properties=GroupRoleAssignmentProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.label,
                displayname=self.label,
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                assignment_type=self.assignment_type,
                type=self.type,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _has_role_assignment_edges(self):
        yield Edge(
            kind=ek.HAS_ROLE_ASSIGNMENT,
            start=EdgePath(value=self.source_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def _has_role_edges(self):
        if self.type != "CUSTOM":
            yield Edge(
                kind=ek.HAS_ROLE,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self.type, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
        else:
            yield Edge(
                kind=ek.HAS_ROLE,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self.role, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _add_member_edges(self):
        # TODO: Either all groups or resource-selected groups
        if self.type == "CUSTOM" and self.role:
            has_group_members_permission = self._lookup.has_role_permission(
                self.role, "okta.groups.members.manage"
            )
            has_group_manage_permissions = self._lookup.has_role_permission(
                self.role, "okta.groups.manage"
            )
            if has_group_manage_permissions or has_group_members_permission:
                for (group_id,) in self._lookup.all_groups():
                    yield Edge(
                        kind=ek.ADD_MEMBER,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group_id, match_by="id"),
                    )

    @property
    def _manage_app_edges(self):
        if self.type == "CUSTOM" and self.role:
            has_permissions = self._lookup.has_role_permission(
                self.role, "okta.groups.manage"
            )
            if has_permissions:
                for (app_id,) in self._lookup.all_applications():
                    yield Edge(
                        kind=ek.MANAGE_APP,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=app_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _reset_factors_edges(self):
        if self.type == "CUSTOM" and self.role:
            required_permissions = [
                "okta.users.credentials.resetFactors",
                "okta.users.credentials.manage",
            ]
            has_permission = any(
                self._lookup.has_role_permission(self.role, permission)
                for permission in required_permissions
            )
            if has_permission:
                for (user_id,) in self._lookup.all_users():
                    yield Edge(
                        kind=ek.RESET_FACTORS,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _reset_password_edges(self):
        if self.type == "CUSTOM" and self.role:
            required_permissions = [
                "okta.users.credentials.resetPassword",
                "okta.users.credentials.manage",
                "okta.users.credentials.manageTemporaryAccessCode",
                "okta.users.manage",
            ]
            has_permission = any(
                self._lookup.has_role_permission(self.role, permission)
                for permission in required_permissions
            )

            if has_permission:
                for (user_id,) in self._lookup.all_users():
                    yield Edge(
                        kind=ek.RESET_PASSWORD,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _group_membership_admin_edges(self):
        if self.type == "GROUP_MEMBERSHIP_ADMIN":
            for (group_id,) in self._lookup.all_groups():
                yield Edge(
                    kind=ek.GROUP_MEMBERSHIP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=group_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _app_admin_edges(self):
        if self.type == "APP_ADMIN":
            for (app_id,) in self._lookup.all_applications():
                yield Edge(
                    kind=ek.APP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=app_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _helpdesk_admin_edges(self):
        # TODO: This can be scoped to users and/or groups
        if self.type == "HELP_DESK_ADMIN":
            # Emit only to scoped target groups
            if self.embedded and self.embedded.targets and self.embedded.targets.groups:
                for group in self.embedded.targets.groups:
                    yield Edge(
                        kind=ek.HELPDESK_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                # No targets specified, emit to all users
                for (user_id,) in self._lookup.all_users():
                    yield Edge(
                        kind=ek.HELPDESK_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _mobile_admin_edges(self):
        if self.type == "MOBILE_ADMIN":
            for (device_id,) in self._lookup.all_devices():
                yield Edge(
                    kind=ek.MOBILE_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=device_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _user_admin_edges(self):
        if self.type == "USER_ADMIN":
            for (user_id,) in self._lookup.all_users():
                yield Edge(
                    kind=ek.GROUP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=user_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

            for (group_id,) in self._lookup.all_groups():
                yield Edge(
                    kind=ek.GROUP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=group_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _org_admin_edges(self):
        if self.type == "ORG_ADMIN":
            # TODO: Add edge to a group
            for (device_id,) in self._lookup.all_devices():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=device_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )
            for (user_id,) in self._lookup.all_users():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=user_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )
            for (app_id,) in self._lookup.all_applications():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=app_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _scoped_to_org_edge(self):
        org_wide_roles = [
            "SUPER_ADMIN",
            "ORG_ADMIN",
            "MOBILE_ADMIN",
            "READ_ONLY_ADMIN",
            "REPORT_ADMIN",
        ]
        if self.type != "CUSTOM" and self.type in org_wide_roles:
            yield Edge(
                kind=ek.SCOPED_TO,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self._lookup.org_id(), match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _scoped_to_group_edges(self):
        if self.embedded and self.embedded.targets.groups:
            for group in self.embedded.targets.groups:
                yield Edge(
                    kind=ek.SCOPED_TO,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=group.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _super_admin_edge(self):
        if self.type == "SUPER_ADMIN":
            yield Edge(
                kind=ek.SUPER_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self._lookup.org_id(), match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def edges(self):
        yield from self._has_role_assignment_edges
        yield from self._has_role_edges
        yield from self._add_member_edges
        yield from self._app_admin_edges
        yield from self._group_membership_admin_edges
        yield from self._helpdesk_admin_edges
        yield from self._mobile_admin_edges
        yield from self._user_admin_edges
        yield from self._super_admin_edge
        yield from self._org_admin_edges
        yield from self._reset_password_edges
        yield from self._reset_factors_edges
        yield from self._manage_app_edges
        yield from self._scoped_to_group_edges
        yield from self._scoped_to_org_edge
        yield from read_client_secret_edges(self)
