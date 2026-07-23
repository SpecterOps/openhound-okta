from datetime import datetime
from typing import Any

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.kinds import edges as ek
from openhound_okta.models.built_in_role import (
    SUPPORTED_ROLE_ASSIGNMENT_TYPES,
    built_in_role_graph_id,
)

DIRECT_ASSIGNMENT_TYPES = {
    "user": "USER",
    "group": "GROUP",
    "client": "CLIENT",
}

ADD_MEMBER_PERMISSIONS = (
    "okta.groups.manage",
    "okta.groups.members.manage",
)

GROUP_TARGETED_ROLE_TYPES = {
    "GROUP_MEMBERSHIP_ADMIN",
    "HELP_DESK_ADMIN",
    "USER_ADMIN",
}

RESOURCE_SET_SCOPED_BUILT_IN_ROLE_TYPES = {
    "WORKFLOWS_ADMIN",
}


class RoleAssignmentAppTarget(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    id: str | None = None
    display_name: str | None = Field(default=None, alias="displayName")
    status: str | None = None
    category: str | None = None


class RoleAssignmentGroupTarget(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str


class RoleAssignment(BaseAsset):
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
    scope_apps: list[RoleAssignmentAppTarget] | None = None
    scope_groups: list[RoleAssignmentGroupTarget] | None = None
    embedded: Any = Field(alias="_embedded", default=None)
    links: Any = Field(alias="_links", default=None)

    @property
    def node_id(self) -> str:
        """Return the OktaHound-compatible unique role assignment node ID."""
        return f"{self.id}_{self.source_id}"

    @property
    def is_direct_active_assignment(self) -> bool:
        expected_assignment_type = DIRECT_ASSIGNMENT_TYPES.get(self.from_resource)
        return (
            self.status == "ACTIVE"
            and expected_assignment_type is not None
            and self.assignment_type == expected_assignment_type
            and self.type in SUPPORTED_ROLE_ASSIGNMENT_TYPES
        )

    @property
    def scoped_group_ids(self) -> tuple[str, ...] | None:
        if self.scope_groups is None:
            return None

        return tuple(
            group.id
            for group in self.scope_groups
            if self._lookup.group_by_id(group.id)
        )

    @property
    def scoped_app_ids(self) -> tuple[str, ...] | None:
        if self.scope_apps is None:
            return None

        target_ids: set[str] = set()
        for app in self.scope_apps:
            if app.status != "ACTIVE":
                continue

            if app.id:
                if self._lookup.application_by_id(app.id):
                    target_ids.add(app.id)
                continue

            target_ids.update(
                app_id for (app_id,) in self._lookup.application_ids_by_name(app.name)
            )
            target_ids.update(
                integration_id
                for (integration_id,) in self._lookup.api_service_ids_by_name(app.name)
            )

        return tuple(sorted(target_ids))

    @property
    def resource_set_ids(self) -> tuple[str, ...]:
        return self._lookup.role_assignment_resource_set_ids(self.id, self.source_id)

    @staticmethod
    def _ids(rows) -> tuple[str, ...]:
        return tuple(row_id for (row_id,) in rows)

    @property
    def _permission_group_ids(self) -> tuple[str, ...] | None:
        scoped_group_ids = self.scoped_group_ids
        if scoped_group_ids is None:
            return None

        target_group_ids = (
            scoped_group_ids
            if scoped_group_ids
            else self._ids(self._lookup.all_groups())
        )
        non_admin_group_ids = set(self._ids(self._lookup.non_admin_groups()))
        return tuple(
            group_id
            for group_id in target_group_ids
            if group_id in non_admin_group_ids
        )

    @property
    def _permission_app_ids(self) -> tuple[str, ...] | None:
        scoped_app_ids = self.scoped_app_ids
        if scoped_app_ids is None:
            return None

        target_app_ids = (
            scoped_app_ids
            if scoped_app_ids
            else self._ids(self._lookup.all_applications())
            + self._ids(self._lookup.all_api_services())
        )
        allowed_target_ids = set(self._ids(self._lookup.non_admin_apps()))
        allowed_target_ids.update(self._ids(self._lookup.all_api_services()))
        return tuple(
            app_id for app_id in target_app_ids if app_id in allowed_target_ids
        )

    @property
    def _permission_user_ids(self) -> tuple[str, ...] | None:
        scoped_group_ids = self.scoped_group_ids
        if scoped_group_ids is None:
            return None

        target_user_ids = (
            self._lookup.group_user_ids(scoped_group_ids)
            if scoped_group_ids
            else self._ids(self._lookup.all_users())
        )
        non_admin_user_ids = set(self._ids(self._lookup.non_admin_users()))
        return tuple(
            user_id for user_id in target_user_ids if user_id in non_admin_user_ids
        )

    @property
    def _bound_resource_set_application_ids(self) -> tuple[str, ...]:
        app_ids: set[str] = set()
        for resource_set_id in self.resource_set_ids:
            app_ids.update(self._lookup.resource_set_application_ids(resource_set_id))
        return tuple(sorted(app_ids))

    @property
    def _bound_resource_set_non_admin_application_ids(self) -> tuple[str, ...]:
        app_ids: set[str] = set()
        for resource_set_id in self.resource_set_ids:
            app_ids.update(
                self._lookup.resource_set_non_admin_application_ids(resource_set_id)
            )
        return tuple(sorted(app_ids))

    @property
    def _bound_resource_set_non_admin_group_ids(self) -> tuple[str, ...]:
        group_ids: set[str] = set()
        for resource_set_id in self.resource_set_ids:
            group_ids.update(
                self._lookup.resource_set_non_admin_group_ids(resource_set_id)
            )
        return tuple(sorted(group_ids))

    @property
    def _bound_resource_set_non_admin_user_ids(self) -> tuple[str, ...]:
        user_ids: set[str] = set()
        for resource_set_id in self.resource_set_ids:
            user_ids.update(
                self._lookup.resource_set_non_admin_user_ids(resource_set_id)
            )
        return tuple(sorted(user_ids))

    @property
    def _has_role_assignment_edges(self):
        yield Edge(
            kind=ek.HAS_ROLE_ASSIGNMENT,
            start=EdgePath(value=self.source_id, match_by="id"),
            end=EdgePath(value=self.node_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.node_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _has_role_edges(self):
        if self.type != "CUSTOM":
            yield Edge(
                kind=ek.HAS_ROLE,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(
                    value=built_in_role_graph_id(self.type, self._extras["tenant"]),
                    match_by="id",
                ),
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
                self.role, "okta.apps.manage"
            )
            if has_permissions:
                for app_id in self._bound_resource_set_non_admin_application_ids:
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
                "okta.users.manage",
            ]
            has_permission = any(
                self._lookup.has_role_permission(self.role, permission)
                for permission in required_permissions
            )
            if has_permission:
                for user_id in self._bound_resource_set_non_admin_user_ids:
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
                "okta.users.credentials.expirePassword",
                "okta.users.manage",
            ]
            has_permission = any(
                self._lookup.has_role_permission(self.role, permission)
                for permission in required_permissions
            )

            if has_permission:
                for user_id in self._bound_resource_set_non_admin_user_ids:
                    yield Edge(
                        kind=ek.RESET_PASSWORD,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=user_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _scoped_to_org_edge(self):
        if (
            self.type == "CUSTOM"
            or self.type in RESOURCE_SET_SCOPED_BUILT_IN_ROLE_TYPES
        ):
            return

        if self.type == "APP_ADMIN":
            scoped_app_ids = self.scoped_app_ids
            if scoped_app_ids is None or scoped_app_ids:
                return

        if self.type in GROUP_TARGETED_ROLE_TYPES:
            scoped_group_ids = self.scoped_group_ids
            if scoped_group_ids is None or scoped_group_ids:
                return

        yield Edge(
            kind=ek.SCOPED_TO,
            start=EdgePath(value=self.node_id, match_by="id"),
            end=EdgePath(value=self._lookup.org_id(), match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def _scoped_to_group_edges(self):
        for group_id in self.scoped_group_ids or ():
            yield Edge(
                kind=ek.SCOPED_TO,
                start=EdgePath(value=self.node_id, match_by="id"),
                end=EdgePath(value=group_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _scoped_to_app_edges(self):
        for app_id in self.scoped_app_ids or ():
            yield Edge(
                kind=ek.SCOPED_TO,
                start=EdgePath(value=self.node_id, match_by="id"),
                end=EdgePath(value=app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _group_membership_admin_edges(self):
        if self.type != "GROUP_MEMBERSHIP_ADMIN":
            return

        target_group_ids = self._permission_group_ids
        if target_group_ids is None:
            return

        for group_id in target_group_ids:
            yield Edge(
                kind=ek.GROUP_MEMBERSHIP_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=group_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _app_admin_edges(self):
        if self.type != "APP_ADMIN":
            return

        target_app_ids = self._permission_app_ids
        if target_app_ids is None:
            return

        for app_id in target_app_ids:
            yield Edge(
                kind=ek.APP_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=app_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _helpdesk_admin_edges(self):
        if self.type != "HELP_DESK_ADMIN":
            return

        target_user_ids = self._permission_user_ids
        if target_user_ids is None:
            return

        for user_id in target_user_ids:
            yield Edge(
                kind=ek.HELPDESK_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=user_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _user_admin_edges(self):
        if self.type != "USER_ADMIN":
            return

        target_group_ids = self._permission_group_ids
        target_user_ids = self._permission_user_ids
        if target_group_ids is None or target_user_ids is None:
            return

        for group_id in target_group_ids:
            yield Edge(
                kind=ek.GROUP_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=group_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

        for user_id in target_user_ids:
            yield Edge(
                kind=ek.GROUP_ADMIN,
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
    def _super_admin_edge(self):
        if self.type == "SUPER_ADMIN":
            yield Edge(
                kind=ek.SUPER_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self._lookup.org_id(), match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def add_member_edges(self):
        expected_assignment_type = DIRECT_ASSIGNMENT_TYPES.get(self.from_resource)
        if (
            self.type != "CUSTOM"
            or not self.role
            or self.status != "ACTIVE"
            or self.assignment_type != expected_assignment_type
        ):
            return

        has_permission = any(
            self._lookup.has_role_permission(self.role, permission)
            for permission in ADD_MEMBER_PERMISSIONS
        )
        if not has_permission:
            return

        for group_id in self._bound_resource_set_non_admin_group_ids:
            yield Edge(
                kind=ek.ADD_MEMBER,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=group_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def read_client_secret_edges(self):
        if self.type == "APP_ADMIN":
            scoped_app_ids = self.scoped_app_ids
            if scoped_app_ids is None:
                return

            if scoped_app_ids:
                app_ids = scoped_app_ids
            else:
                app_ids = [app_id for (app_id,) in self._lookup.all_applications()]

            for app_id in app_ids:
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

        elif self.type in ["API_ACCESS_MANAGEMENT_ADMIN", "READ_ONLY_ADMIN"]:
            for (app_id,) in self._lookup.all_applications():
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

        elif (
            self.type == "CUSTOM"
            and self.role
            and self._lookup.has_role_permission(
                self.role, "okta.apps.clientCredentials.read"
            )
        ):
            for app_id in self._bound_resource_set_application_ids:
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
