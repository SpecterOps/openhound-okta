from datetime import datetime

from dlt.common import json
from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.hybrid_auth import (
    hybrid_group_target,
    hybrid_target_edge_path,
)


@app.asset(
    description="Okta application group mappings (push)",
    edges=[
        EdgeDef(
            start=nk.GROUP,
            end=nk.APPLICATION,
            kind=ek.GROUP_PUSH,
            description="Group is pushed to application",
            traversable=False,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.AD_GROUP,
            kind=ek.MEMBERSHIP_SYNC,
            description="Group membership is synchronized to Active Directory",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.MEMBERSHIP_SYNC,
            description="Group membership is synchronized to another Okta organization",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.AZ_GROUP,
            kind=ek.MEMBERSHIP_SYNC,
            description="Group membership is synchronized to Entra ID",
            traversable=True,
        ),
    ],
)
class ApplicationGroupMapping(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    created: datetime | None = None
    error_summary: str | None = Field(alias="errorSummary", default=None)
    id: str
    status: str | None = None
    source_group_id: str = Field(alias="sourceGroupId")
    target_group_id: str = Field(alias="targetGroupId")
    last_push: datetime | None = Field(alias="lastPush", default=None)
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)

    # Additional
    app_id: str
    app_name: str
    target_group_name: str | None = None

    @property
    def as_node(self):
        return None

    @property
    def _membership_sync_edge(self):
        if not self.target_group_name:
            return

        app_settings = self._lookup.application_settings(self.app_id)
        if not app_settings:
            return

        app_settings_obj = json.loads(app_settings)
        target = hybrid_group_target(
            self.app_name,
            app_settings_obj.get("app"),
            group_name=self.target_group_name,
        )
        if target is None:
            return

        yield Edge(
            kind=ek.MEMBERSHIP_SYNC,
            start=EdgePath(value=self.source_group_id, match_by="id"),
            end=hybrid_target_edge_path(target),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.GROUP_PUSH,
            start=EdgePath(value=self.source_group_id, match_by="id"),
            end=EdgePath(value=self.app_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
        yield from self._membership_sync_edge
