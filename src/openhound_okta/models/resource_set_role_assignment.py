from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.resource_set import resource_set_node_id


@app.asset(
    description="Okta resource set role assignment scope",
    edges=[
        EdgeDef(
            start=nk.ROLE_ASSIGNMENT,
            end=nk.RESOURCE_SET,
            kind=ek.SCOPED_TO,
            description="Role assignment is scoped to resource set",
            traversable=False,
        ),
    ],
)
class ResourceSetRoleAssignment(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    resource_set_id: str
    role_id: str
    assignee_id: str
    created: datetime | None = None
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    links: dict | None = Field(default=None, alias="_links")

    @property
    def role_assignment_node_id(self) -> str:
        return f"{self.id}_{self.assignee_id}"

    @property
    def resource_set_node_id(self) -> str:
        return resource_set_node_id(
            self.resource_set_id,
            getattr(self, "_extras", {}).get("tenant"),
        )

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        if not self._lookup.role_assignment_exists(self.id, self.assignee_id):
            return

        yield Edge(
            kind=ek.SCOPED_TO,
            start=EdgePath(value=self.role_assignment_node_id, match_by="id"),
            end=EdgePath(value=self.resource_set_node_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
