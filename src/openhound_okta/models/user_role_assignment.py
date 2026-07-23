from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.role_assignment import RoleAssignment


@dataclass
class UserRoleAssignmentProperties(OktaNodeProperties):
    id: str
    okta_domain: str
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


class HREF(BaseModel):
    href: str


class Links(BaseModel):
    source: HREF | None = None
    users: HREF | None = None
    apps: HREF | None = None
    groups: HREF | None = None


class Embedded(BaseModel):
    targets: Target | None = None


@app.asset(
    description="Okta role assignment",
    node=NodeDef(
        icon="clipboard-check",
        kind=nk.ROLE_ASSIGNMENT,
        description="Okta role assignment node",
        properties=UserRoleAssignmentProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.ROLE_ASSIGNMENT,
            kind=ek.CONTAINS,
            description="Organization contains role assignment",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.ROLE_ASSIGNMENT,
            kind=ek.HAS_ROLE_ASSIGNMENT,
            description="User has a role assignment",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.ROLE_ASSIGNMENT,
            kind=ek.HAS_ROLE_ASSIGNMENT,
            description="Group has a role assignment",
            traversable=False,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.ROLE,
            kind=ek.HAS_ROLE,
            description="User is assigned a built-in role",
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
            start=nk.USER,
            end=nk.CUSTOM_ROLE,
            kind=ek.HAS_ROLE,
            description="User is assigned a custom role",
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
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="User can add member to groups",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="Application can add member to groups",
            traversable=True,
        ),
        # Group Admin Role (USER_ADMIN in OktaHound)
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Group has group admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="User has group admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Application has group admin role",
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
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="User has group admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="Application has group admin role",
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
            start=nk.USER,
            end=nk.APPLICATION,
            kind=ek.APP_ADMIN,
            description="User has app admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.APPLICATION,
            kind=ek.APP_ADMIN,
            description="Application has app admin role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.INTEGRATION,
            kind=ek.APP_ADMIN,
            description="User has app admin role for API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.INTEGRATION,
            kind=ek.APP_ADMIN,
            description="Group has app admin role for API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.INTEGRATION,
            kind=ek.APP_ADMIN,
            description="Application has app admin role for API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.CLIENT_SECRET,
            kind=ek.READ_CLIENT_SECRET,
            description="User can read application client secrets",
            traversable=True,
        ),
        # Group Membership Role
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.GROUP_MEMBERSHIP_ADMIN,
            description="Group has app GROUP_MEMBERSHIP_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.GROUP_MEMBERSHIP_ADMIN,
            description="User has GROUP_MEMBERSHIP_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_MEMBERSHIP_ADMIN,
            description="Application has GROUP_MEMBERSHIP_ADMIN role",
            traversable=True,
        ),
        # Helpdesk role
        EdgeDef(
            start=nk.GROUP,
            end=nk.USER,
            kind=ek.HELPDESK_ADMIN,
            description="Group has HELPDESK_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.USER,
            kind=ek.HELPDESK_ADMIN,
            description="User has HELPDESK_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.HELPDESK_ADMIN,
            description="Application has HELPDESK_ADMIN role",
            traversable=True,
        ),
        # Mobile admin role
        EdgeDef(
            start=nk.GROUP,
            end=nk.DEVICE,
            kind=ek.MOBILE_ADMIN,
            description="Group has app MOBILE_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.DEVICE,
            kind=ek.MOBILE_ADMIN,
            description="User has MOBILE_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.DEVICE,
            kind=ek.MOBILE_ADMIN,
            description="Application has MOBILE_ADMIN role",
            traversable=True,
        ),
        # Org admin
        EdgeDef(
            start=nk.USER,
            end=nk.USER,
            kind=ek.ORG_ADMIN,
            description="Group has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.ORG_ADMIN,
            description="User has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.DEVICE,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=True,
        ),
        # Org admin
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
        # Org admin
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.DEVICE,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=True,
        ),
        # Super admin
        EdgeDef(
            start=nk.USER,
            end=nk.ORG,
            kind=ek.SUPER_ADMIN,
            description="User has SUPER_ADMIN role",
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
            start=nk.APPLICATION,
            end=nk.ORG,
            kind=ek.SUPER_ADMIN,
            description="Application has SUPER_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="User has GROUP_ADMIN role",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="User has GROUP_ADMIN role",
            traversable=True,
        ),
        # Scoped to
        EdgeDef(
            start=nk.ROLE_ASSIGNMENT,
            end=nk.GROUP,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to group",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ROLE_ASSIGNMENT,
            end=nk.ORG,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to org",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ROLE_ASSIGNMENT,
            end=nk.APPLICATION,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to application",
            traversable=False,
        ),
        EdgeDef(
            start=nk.ROLE_ASSIGNMENT,
            end=nk.INTEGRATION,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to API service integration",
            traversable=False,
        ),
    ],
)
class UserRoleAssignment(RoleAssignment):
    model_config = ConfigDict(populate_by_name=True)

    embedded: Embedded | None = Field(alias="_embedded", default=None)
    links: Links | None = Field(alias="_links", default=None)

    @property
    def as_node(self):
        if not self.is_direct_active_assignment:
            return None

        return OktaNode(
            kinds=[nk.ROLE_ASSIGNMENT],
            properties=UserRoleAssignmentProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.node_id,
                name=self.label,
                displayname=self.label,
                okta_domain=self._extras["tenant"],
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                assignment_type=self.assignment_type,
                type=self.type,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _group_membership_admin_edges(self):
        yield from super()._group_membership_admin_edges

    @property
    def _app_admin_edges(self):
        yield from super()._app_admin_edges

    @property
    def _helpdesk_admin_edges(self):
        yield from super()._helpdesk_admin_edges

    @property
    def _org_admin_edges(self):
        """
        ORG_ADMIN permission edges: (:Assignee)-[:Okta_OrgAdmin]->(:User|:Group|:Device|:Application)
        Org admins have permissions on users, groups, and devices.
        If role has specific targets, emit edges only to those targets.
        If no targets, emit to all users, groups, devices, and applications.
        Entities with role assignments cannot be managed by ORG_ADMIN.
        """
        if self.type == "ORG_ADMIN":
            has_targets = (
                    self.embedded
                    and self.embedded.targets
                    and (
                            (
                                    self.embedded.targets.groups
                                    and len(self.embedded.targets.groups) > 0
                            )
                            or (
                                    self.embedded.targets.catalog
                                    and self.embedded.targets.catalog.apps
                                    and len(self.embedded.targets.catalog.apps) > 0
                            )
                    )
            )

            if has_targets:
                # Emit only to scoped targets
                if self.embedded.targets.groups:
                    for group in self.embedded.targets.groups:
                        yield Edge(
                            kind=ek.ORG_ADMIN,
                            start=EdgePath(value=self.source_id, match_by="id"),
                            end=EdgePath(value=group.id, match_by="id"),
                            properties=EdgeProperties(traversable=True),
                        )

                if self.embedded.targets.catalog and self.embedded.targets.catalog.apps:
                    for app in self.embedded.targets.catalog.apps:
                        if app.id:
                            yield Edge(
                                kind=ek.ORG_ADMIN,
                                start=EdgePath(value=self.source_id, match_by="id"),
                                end=EdgePath(value=app.id, match_by="id"),
                                properties=EdgeProperties(traversable=True),
                            )
            else:
                # No targets specified, emit to all users, groups, devices, and apps
                all_devices = self._lookup.all_devices()
                for (device_id,) in all_devices:
                    yield Edge(
                        kind=ek.ORG_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=device_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

                all_users = self._lookup.all_users()
                for (user_id,) in all_users:
                    yield Edge(
                        kind=ek.ORG_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

                all_groups = self._lookup.all_groups()
                for (group_id,) in all_groups:
                    yield Edge(
                        kind=ek.ORG_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

                all_apps = self._lookup.all_applications()
                for (app_id,) in all_apps:
                    yield Edge(
                        kind=ek.ORG_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=app_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _user_admin_edges(self):
        yield from super()._user_admin_edges

    @property
    def edges(self):
        if not self.is_direct_active_assignment:
            return

        yield from self._contains_edge
        yield from self._has_role_assignment_edges
        yield from self._has_role_edges
        yield from self._app_admin_edges
        yield from self._group_membership_admin_edges
        yield from self._helpdesk_admin_edges
        yield from self._mobile_admin_edges
        yield from self._super_admin_edge
        yield from self._org_admin_edges
        yield from self._user_admin_edges
        yield from self._manage_app_edges
        yield from self._reset_factors_edges
        yield from self._reset_password_edges
        yield from self._scoped_to_app_edges
        yield from self._scoped_to_group_edges
        yield from self._scoped_to_org_edge
        yield from self.read_client_secret_edges
        yield from self.add_member_edges
