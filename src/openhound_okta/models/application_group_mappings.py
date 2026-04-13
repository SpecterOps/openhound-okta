from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@app.asset(
    description="Okta application group mappings (push)",
    edges=[
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_PUSH,
            description="Application pushes group mapping",
            traversable=False,
        ),
    ],
)
class ApplicationGroupMapping(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    created: datetime | None = None
    error_summary: str | None = Field(alias="errorSummary", default=None)
    id: str
    status: str
    target_group_id: str = Field(alias="targetGroupId")
    last_push: datetime | None = Field(alias="lastPush", default=None)
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)

    # Additional
    app_id: str
    app_name: str

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        yield Edge(
            kind=ek.GROUP_PUSH,
            start=EdgePath(value=self.app_id, match_by="id"),
            end=EdgePath(value=self.target_group_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
