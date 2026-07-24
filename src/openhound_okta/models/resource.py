from datetime import datetime
from collections.abc import Mapping

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.resource_set import resource_set_node_id


@app.asset(
    description="Okta resource set contains resource",
    edges=[
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.USER,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.GROUP,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains group",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.APPLICATION,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains application",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.INTEGRATION,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.DEVICE,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains device",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.AUTH_SERVER,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains auth server",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.IDP,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains IDP",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.POLICY,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains policy",
            traversable=True,
        ),
    ],
)
class Resource(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    orn: str
    created: datetime | None = None
    links: dict | None = Field(default=None, alias="_links")

    # Additional
    resource_set_id: str

    @property
    def resource_type(self):
        split_orn = self.orn.split(":")
        resource_type = split_orn[-1] if len(split_orn) == 5 else split_orn[-2]
        return resource_type

    @property
    def resource_id(self):
        split_orn = self.orn.split(":")
        resource_id = split_orn[-1] if len(split_orn) == 6 else None
        return resource_id

    @property
    def as_node(self):
        return None

    @property
    def resource_url(self) -> str | None:
        if not self.links:
            return None

        self_link = self.links.get("self")
        if not isinstance(self_link, Mapping):
            return None

        href = self_link.get("href")
        return href if isinstance(href, str) and href else None

    @property
    def resource_set_node_id(self) -> str:
        return resource_set_node_id(
            self.resource_set_id,
            getattr(self, "_extras", {}).get("tenant"),
        )

    def _yield_edge(self, target_id: str):
        yield Edge(
            kind=ek.RESOURCE_SET_CONTAINS,
            start=EdgePath(value=self.resource_set_node_id, match_by="id"),
            end=EdgePath(value=target_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        resource_url = self.resource_url
        target_ids = (
            self._lookup.resolve_resource_url(resource_url)
            if resource_url
            else self._lookup.resolve_resource_orn(self.orn)
        )

        for target_id in target_ids:
            yield from self._yield_edge(target_id)
