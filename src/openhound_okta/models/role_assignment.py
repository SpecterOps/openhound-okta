from datetime import datetime
from typing import Any

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import Field

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
    embedded: Any = Field(alias="_embedded", default=None)
    links: Any = Field(alias="_links", default=None)

    @property
    def _has_role_assignment_edges(self):
        yield Edge(
            kind=ek.HAS_ROLE_ASSIGNMENT,
            start=EdgePath(value=self.source_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=ek.traversable(ek.HAS_ROLE_ASSIGNMENT)),
        )

    @property
    def _has_role_edges(self):
        if self.type != "CUSTOM":
            yield Edge(
                kind=ek.HAS_ROLE,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self.type, match_by="id"),
                properties=EdgeProperties(traversable=ek.traversable(ek.HAS_ROLE)),
            )
        else:
            yield Edge(
                kind=ek.HAS_ROLE,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self.role, match_by="id"),
                properties=EdgeProperties(traversable=ek.traversable(ek.HAS_ROLE)),
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
                        properties=EdgeProperties(traversable=ek.traversable(ek.MANAGE_APP)),
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
                        properties=EdgeProperties(traversable=ek.traversable(ek.RESET_FACTORS)),
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
                        properties=EdgeProperties(traversable=ek.traversable(ek.RESET_PASSWORD)),
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
                properties=EdgeProperties(traversable=ek.traversable(ek.SCOPED_TO)),
            )

    @property
    def _scoped_to_group_edges(self):
        if self.embedded and self.embedded.targets and self.embedded.targets.groups:
            for group in self.embedded.targets.groups:
                yield Edge(
                    kind=ek.SCOPED_TO,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=group.id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.SCOPED_TO)),
                )

    @property
    def _mobile_admin_edges(self):
        if self.type == "MOBILE_ADMIN":
            for (device_id,) in self._lookup.all_devices():
                yield Edge(
                    kind=ek.MOBILE_ADMIN,
                    start=EdgePath(value=self.source_id, match_by="id"),
                    end=EdgePath(value=device_id, match_by="id"),
                    properties=EdgeProperties(traversable=ek.traversable(ek.MOBILE_ADMIN)),
                )

    @property
    def _super_admin_edge(self):
        if self.type == "SUPER_ADMIN":
            yield Edge(
                kind=ek.SUPER_ADMIN,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=self._lookup.org_id(), match_by="id"),
                properties=EdgeProperties(traversable=ek.traversable(ek.SUPER_ADMIN)),
            )

    @property
    def add_member_edges(self):
        expected_assignment_type = DIRECT_ASSIGNMENT_TYPES.get(self.from_resource)
        if (
            self.type != "CUSTOM"
            or not self.role
            or self.status != "ACTIVE"
            or self.assignment_type != expected_assignment_type
            or not self.resource_set
        ):
            return

        has_permission = any(
            self._lookup.has_role_permission(self.role, permission)
            for permission in ADD_MEMBER_PERMISSIONS
        )
        if not has_permission:
            return

        for group_id in self._lookup.resource_set_non_admin_group_ids(self.resource_set):
            yield Edge(
                kind=ek.ADD_MEMBER,
                start=EdgePath(value=self.source_id, match_by="id"),
                end=EdgePath(value=group_id, match_by="id"),
            )

    @property
    def read_client_secret_edges(self):
        if self.type == "APP_ADMIN":
            embedded = self.embedded
            if (
                embedded
                and embedded.targets
                and embedded.targets.catalog
                and embedded.targets.catalog.apps
            ):
                app_ids = [app.id for app in embedded.targets.catalog.apps if app.id]
            else:
                app_ids = [app_id for (app_id,) in self._lookup.all_applications()]

            for app_id in app_ids:
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=ek.traversable(ek.READ_CLIENT_SECRET)),
                    )

        elif self.type in ["API_ACCESS_MANAGEMENT_ADMIN", "READ_ONLY_ADMIN"]:
            for (app_id,) in self._lookup.all_applications():
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=ek.traversable(ek.READ_CLIENT_SECRET)),
                    )

        elif (
            self.type == "CUSTOM"
            and self.role
            and self.resource_set
            and self._lookup.has_role_permission(
                self.role, "okta.apps.clientCredentials.read"
            )
        ):
            for app_id in self._lookup.resource_set_application_ids(self.resource_set):
                for (secret_id,) in self._lookup.application_secret_ids(app_id):
                    yield Edge(
                        kind=ek.READ_CLIENT_SECRET,
                        start=EdgePath(value=self.source_id, match_by="id"),
                        end=EdgePath(value=secret_id, match_by="id"),
                        properties=EdgeProperties(traversable=ek.traversable(ek.READ_CLIENT_SECRET)),
                    )
