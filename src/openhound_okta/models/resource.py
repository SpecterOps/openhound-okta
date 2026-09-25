from datetime import datetime
from collections.abc import Iterator, Mapping

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import ConfigDict, Field, PrivateAttr

from openhound_okta.graph import OktaOwnedEdgePath
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.lookup import OktaLookup
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
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.GROUP,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains group",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.APPLICATION,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains application",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.INTEGRATION,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains API service integration",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.DEVICE,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains device",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.AUTH_SERVER,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains auth server",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.IDP,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains IDP",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.POLICY,
            kind=ek.RESOURCE_SET_CONTAINS,
            description="Resource set contains policy",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.GROUP,
            kind=ek.RESOURCE_SET_CONTAINS_MEMBERS_OF,
            description="Resource set contains the members of a group",
            traversable=False,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.USER,
            kind=ek.RESOURCE_SET_CONTAINS_INDIRECT,
            description="Resource set contains user through a group membership",
            traversable=False,
        ),
    ],
)
class Resource(BaseAsset):
    # Narrow the BaseAsset annotation: openhound injects the lookup class
    # registered via @app.convert, which is OktaLookup for this source.
    _lookup: OktaLookup = PrivateAttr()

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

    def _yield_edge(self, kind: str, target_id: str) -> Iterator[Edge]:
        yield Edge(
            kind=kind,
            start=OktaOwnedEdgePath(value=self.resource_set_node_id, match_by="id"),
            end=OktaOwnedEdgePath(value=target_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def edges(self):
        resource_url = self.resource_url
        member_group_id = self._lookup.resource_member_group_id(resource_url, self.orn)
        if member_group_id is not None:
            # The resource set contains the members of a group rather than the
            # group itself. Emit a marker edge to the group and an indirect
            # membership edge to each of its current members.
            if self._lookup.group_by_id(member_group_id):
                yield from self._yield_edge(
                    ek.RESOURCE_SET_CONTAINS_MEMBERS_OF, member_group_id
                )
            for user_id in self._lookup.group_user_ids((member_group_id,)):
                yield from self._yield_edge(ek.RESOURCE_SET_CONTAINS_INDIRECT, user_id)
            return

        target_ids = (
            self._lookup.resolve_resource_url(resource_url)
            if resource_url
            else self._lookup.resolve_resource_orn(self.orn)
        )

        for target_id in target_ids:
            yield from self._yield_edge(ek.RESOURCE_SET_CONTAINS, target_id)
