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
class ClientRoleAssignmentProperties(OktaNodeProperties):
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
    description="Okta client (application) role assignment",
    node=NodeDef(
        icon="clipboard-check",
        kind=nk.ROLE_ASSIGNMENT,
        description="Okta client (application) role assignment node",
        properties=ClientRoleAssignmentProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.ROLE_ASSIGNMENT,
            kind=ek.HAS_ROLE_ASSIGNMENT,
            description="Application has a role assignment",
            traversable=ek.traversable(ek.HAS_ROLE_ASSIGNMENT),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.ROLE,
            kind=ek.HAS_ROLE,
            description="Application is assigned a built-in role",
            traversable=ek.traversable(ek.HAS_ROLE),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.CUSTOM_ROLE,
            kind=ek.HAS_ROLE,
            description="Application is assigned a custom role",
            traversable=ek.traversable(ek.HAS_ROLE),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.ADD_MEMBER,
            description="Application can add member to groups",
            traversable=ek.traversable(ek.ADD_MEMBER),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.APPLICATION,
            kind=ek.APP_ADMIN,
            description="Application has app admin role",
            traversable=ek.traversable(ek.APP_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.CLIENT_SECRET,
            kind=ek.READ_CLIENT_SECRET,
            description="Application can read application client secrets",
            traversable=ek.traversable(ek.READ_CLIENT_SECRET),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_MEMBERSHIP_ADMIN,
            description="Application has GROUP_MEMBERSHIP_ADMIN role",
            traversable=ek.traversable(ek.GROUP_MEMBERSHIP_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Application has group admin role",
            traversable=ek.traversable(ek.GROUP_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="Application has group admin role for groups",
            traversable=ek.traversable(ek.GROUP_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.HELPDESK_ADMIN,
            description="Application has HELPDESK_ADMIN role",
            traversable=ek.traversable(ek.HELPDESK_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.DEVICE,
            kind=ek.MOBILE_ADMIN,
            description="Application has MOBILE_ADMIN role",
            traversable=ek.traversable(ek.MOBILE_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=ek.traversable(ek.ORG_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=ek.traversable(ek.ORG_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.DEVICE,
            kind=ek.ORG_ADMIN,
            description="Application has ORG_ADMIN role",
            traversable=ek.traversable(ek.ORG_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.ORG,
            kind=ek.SUPER_ADMIN,
            description="Application has SUPER_ADMIN role",
            traversable=ek.traversable(ek.SUPER_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_ADMIN,
            description="Application has GROUP_ADMIN role",
            traversable=ek.traversable(ek.GROUP_ADMIN),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.USER,
            kind=ek.GROUP_ADMIN,
            description="Application has GROUP_ADMIN role",
            traversable=ek.traversable(ek.GROUP_ADMIN),
        ),
        # Scoped to
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to group",
            traversable=ek.traversable(ek.SCOPED_TO),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.ORG,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to org",
            traversable=ek.traversable(ek.SCOPED_TO),
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.APPLICATION,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to application",
            traversable=ek.traversable(ek.SCOPED_TO),
        ),
    ],
)
class ClientRoleAssignment(RoleAssignment):
    model_config = ConfigDict(populate_by_name=True)

    embedded: Embedded | None = Field(alias="_embedded", default=None)
    links: Links | None = Field(alias="_links", default=None)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.ROLE_ASSIGNMENT],
            properties=ClientRoleAssignmentProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
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
    def _group_membership_admin_edges(self):
        if self.type == "GROUP_MEMBERSHIP_ADMIN":
            for (group_id,) in self._lookup.all_groups():
                yield Edge(
                    kind=ek.GROUP_MEMBERSHIP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=group_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.GROUP_MEMBERSHIP_ADMIN)),
                )

    @property
    def _app_admin_edges(self):
        if self.type == "APP_ADMIN":
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
                            properties=EdgeProperties(traversable=ek.traversable(ek.APP_ADMIN)),
                        )

            else:
                for (app_id,) in self._lookup.all_applications():
                    yield Edge(
                        kind=ek.APP_ADMIN,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=app_id, match_by="id"),
                        properties=EdgeProperties(traversable=ek.traversable(ek.APP_ADMIN)),
                    )

    @property
    def _helpdesk_admin_edges(self):
        if self.type == "HELP_DESK_ADMIN":
            for (user_id,) in self._lookup.all_users():
                yield Edge(
                    kind=ek.HELPDESK_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=user_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.HELPDESK_ADMIN)),
                )

    @property
    def _org_admin_edges(self):
        if self.type == "ORG_ADMIN":
            for (device_id,) in self._lookup.all_devices():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=device_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.ORG_ADMIN)),
                )
            for (user_id,) in self._lookup.all_users():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=user_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.ORG_ADMIN)),
                )
            for (app_id,) in self._lookup.all_applications():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=app_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.ORG_ADMIN)),
                )

            for (group_id,) in self._lookup.all_groups():
                yield Edge(
                    kind=ek.ORG_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=group_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.ORG_ADMIN)),
                )

    @property
    def _user_admin_edges(self):
        if self.type == "USER_ADMIN":
            for (user_id,) in self._lookup.all_users():
                yield Edge(
                    kind=ek.GROUP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=user_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.GROUP_ADMIN)),
                )

            for (group_id,) in self._lookup.all_groups():
                yield Edge(
                    kind=ek.GROUP_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=group_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.GROUP_ADMIN)),
                )

    @property
    def edges(self):
        yield from self._has_role_assignment_edges
        yield from self._has_role_edges
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
        yield from self.read_client_secret_edges
        yield from self.add_member_edges
