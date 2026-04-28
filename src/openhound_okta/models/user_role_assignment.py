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
class UserRoleAssignmentProperties(OktaNodeProperties):
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
    description="Okta role assignment",
    node=NodeDef(
        icon="clipboard-check",
        kind=nk.ROLE_ASSIGNMENT,
        description="Okta role assignment node",
        properties=UserRoleAssignmentProperties,
    ),
    edges=[
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
            traversable=False,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="User can add member to groups",
            traversable=False,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="Application can add member to groups",
            traversable=False,
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
            start=nk.USER,
            end=nk.GROUP,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to group",
            traversable=False,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.ORG,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to org",
            traversable=False,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.APPLICATION,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to application",
            traversable=False,
        ),
    ],
)
class UserRoleAssignment(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    # Base response via when listing assignments
    id: str

    # Additional
    from_resource: str
    source_id: str

    # Details when fetching user/group
    assignment_type: str = Field(alias="assignmentType")
    resource_set: str | None = Field(alias="resource-set", default=None)
    status: str
    created: datetime | None
    name: str | None = None
    label: str
    status: str
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)
    created: datetime | None
    features: list[str] = Field(default_factory=list)
    type: str
    role: str | None = None

    embedded: Embedded | None = Field(alias="_embedded", default=None)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.ROLE_ASSIGNMENT],
            properties=UserRoleAssignmentProperties(
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
    def _add_member_edges(self):
        if self.type == "CUSTOM" and self.role:
            has_group_members_permission = self._lookup.has_role_permission(
                self.role, "okta.groups.members.manage"
            )
            has_group_manage_permissions = self._lookup.has_role_permission(
                self.role, "okta.groups.manage"
            )
            if has_group_manage_permissions or has_group_members_permission:
                all_groups = self._lookup.all_groups()
                for (group_id,) in all_groups:
                    yield Edge(
                        kind=ek.ADD_MEMBER,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group_id, match_by="id"),
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
    def _scoped_to_app_edges(self):
        if (
                self.embedded
                and self.embedded.targets
                and self.embedded.targets.catalog
                and self.embedded.targets.catalog.apps
        ):
            for app in self.embedded.targets.catalog.apps:
                if app.id:
                    yield Edge(
                        kind=ek.SCOPED_TO,
                        start=EdgePath(value=self.id, match_by="id"),
                        end=EdgePath(value=app.id, match_by="id"),
                        properties=EdgeProperties(traversable=False),
                    )

    @property
    def _scoped_to_group_edges(self):
        if self.embedded and self.embedded.targets and self.embedded.targets.groups:
            for group in self.embedded.targets.groups:
                yield Edge(
                    kind=ek.SCOPED_TO,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=group.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _group_membership_admin_edges(self):
        """
        GROUP_MEMBERSHIP_ADMIN permission edges: (:Assignee)-[:Okta_GroupMembershipAdmin]->(:Group)
        If role has specific group targets, emit edges only to those groups.
        If no targets, emit to all groups in the organization.
        Groups with role assignments cannot be managed by GROUP_MEMBERSHIP_ADMIN.
        """
        if self.type == "GROUP_MEMBERSHIP_ADMIN":
            if self.embedded and self.embedded.targets and self.embedded.targets.groups:
                # Emit only to scoped target groups
                for group in self.embedded.targets.groups:
                    yield Edge(
                        kind=ek.GROUP_MEMBERSHIP_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                # No targets specified, emit to all groups
                all_groups = self._lookup.all_groups()
                for (group_id,) in all_groups:
                    yield Edge(
                        kind=ek.GROUP_MEMBERSHIP_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _app_admin_edges(self):
        """
        APP_ADMIN permission edges: (:Assignee)-[:Okta_AppAdmin]->(:Application)
        Emit edges to all apps in the organization.
        """
        if self.type == "APP_ADMIN":
            # Get targets from embedded data, or all apps if no targets
            if (
                    self.embedded
                    and self.embedded.targets
                    and self.embedded.targets.catalog
                    and self.embedded.targets.catalog.apps
            ):
                # Emit only to scoped targets
                for app in self.embedded.targets.catalog.apps:
                    if app.id:
                        yield Edge(
                            kind=ek.APP_ADMIN,
                            start=EdgePath(value=self.source_id, match_by="id"),
                            end=EdgePath(value=app.id, match_by="id"),
                            properties=EdgeProperties(traversable=True),
                        )
            else:
                # No targets specified, emit to all apps and API service integrations
                for (app_id,) in self._lookup.all_applications():
                    yield Edge(
                        kind=ek.APP_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=app_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _helpdesk_admin_edges(self):
        """
        HELPDESK_ADMIN permission edges: (:Assignee)-[:Okta_HelpDeskAdmin]->(:User)
        If role has specific group targets, emit edges to users in those groups.
        If no targets, emit to all users in the organization.
        Users with role assignments cannot be managed by HELPDESK_ADMIN.
        """
        if self.type == "HELP_DESK_ADMIN":
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
                all_users = self._lookup.all_users()
                for (user_id,) in all_users:
                    yield Edge(
                        kind=ek.HELPDESK_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _mobile_admin_edges(self):
        if self.type == "MOBILE_ADMIN":
            all_devices = self._lookup.all_devices()
            for (device_id,) in all_devices:
                yield Edge(
                    kind=ek.MOBILE_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=device_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

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
    def _super_admin_edge(self):
        if self.type == "SUPER_ADMIN":
            yield Edge(
                kind=ek.SUPER_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self._lookup.org_id(), match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _user_admin_edges(self):
        """
        USER_ADMIN (Group Administrator) permission edges: (:Assignee)-[:Okta_GroupAdmin]->(:User|:Group)
        If role has specific group targets, emit edges to users in those groups.
        If no targets, emit to all users and groups in the organization.
        Users/Groups with role assignments cannot be managed by GROUP_ADMIN.
        """
        if self.type == "USER_ADMIN":
            if self.embedded and self.embedded.targets and self.embedded.targets.groups:
                # Emit only to scoped target groups
                for group in self.embedded.targets.groups:
                    yield Edge(
                        kind=ek.GROUP_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=group.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                # No targets specified, emit to all users and groups
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
    def edges(self):
        yield from self._has_role_assignment_edges
        yield from self._has_role_edges
        yield from self._add_member_edges
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
        yield from read_client_secret_edges(self)
