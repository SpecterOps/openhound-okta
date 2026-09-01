from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Any

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaOwnedEdgePath
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


class Settings(BaseModel):
    app: dict | None = None
    notifications: dict | None = None
    manual_provisioning: bool | None = Field(default=None, alias="manualProvisioning")
    implicit_assignment: bool | None = Field(default=None, alias="implicitAssignment")
    em_opt_in_status: str | None = Field(default=None, alias="emOptInStatus")
    notes: dict | None = None
    oauth_client: dict | None = Field(default=None, alias="oauthClient")


class Credentials(BaseModel):
    user_name_template: dict | None = Field(default=None, alias="userNameTemplate")
    signing: dict | None = None
    oauth_client: dict | None = Field(default=None, alias="oauthClient")


@dataclass
class AppAssignmentEdgeProperties(EdgeProperties):
    """Non-sensitive provenance for a native Okta application assignment.

    Attributes:
        assignment_last_updated: Timestamp of the native Okta assignment update.
        assignment_priority: Native Okta group-assignment priority.
        assignment_profile_fields: Sorted assignment-profile field names. Values
            are intentionally excluded because they may contain sensitive data.
    """

    assignment_last_updated: datetime | None = None
    assignment_priority: int | None = None
    assignment_profile_fields: list[str] = dc_field(default_factory=list)


@app.asset(
    description="Okta assigned application asset",
    edges=[
        EdgeDef(
            kind=ek.APP_ASSIGNMENT,
            start=nk.GROUP,
            end=nk.APPLICATION,
            description="Group is assigned to an application",
        )
    ],
)
class GroupAssignedApp(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    label: str
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")

    group_id: str
    # Retained in raw/preprocessed evidence for later SAML compactability checks.
    app_sign_on_mode: str | None = None
    assignment_last_updated: datetime | None = None
    assignment_priority: int | None = None
    assignment_profile: dict[str, Any] | None = None

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        lookup = getattr(self, "_lookup", None)
        group_by_id = getattr(lookup, "group_by_id", None)
        if not self.group_id:
            raise ValueError("application-group assignment is missing its group ID")
        if not callable(group_by_id):
            raise RuntimeError(
                "application-group assignment conversion requires group lookup"
            )
        if not group_by_id(self.group_id):
            raise ValueError(
                "application-group assignment references uncollected Okta group "
                f"{self.group_id} for application {self.id}"
            )

        yield Edge(
            kind=ek.APP_ASSIGNMENT,
            start=OktaOwnedEdgePath(value=self.group_id, match_by="id"),
            end=OktaOwnedEdgePath(value=self.id, match_by="id"),
            properties=AppAssignmentEdgeProperties(
                traversable=False,
                assignment_last_updated=self.assignment_last_updated,
                assignment_priority=self.assignment_priority,
                assignment_profile_fields=(
                    sorted(self.assignment_profile) if self.assignment_profile else []
                ),
            ),
        )
