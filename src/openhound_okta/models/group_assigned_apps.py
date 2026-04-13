from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

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

    # Additional
    group_id: str

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        yield Edge(
            kind=ek.APP_ASSIGNMENT,
            start=EdgePath(value=self.group_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
