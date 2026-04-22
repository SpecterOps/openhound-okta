from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@app.asset(
    description="Okta resource set contains resource",
    edges=[
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.USER,
            kind=ek.CONTAINS,
            description="Resource set contains user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.GROUP,
            kind=ek.CONTAINS,
            description="Resource set contains group",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.APPLICATION,
            kind=ek.CONTAINS,
            description="Resource set contains application",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.INTEGRATION,
            kind=ek.CONTAINS,
            description="Resource set contains API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.DEVICE,
            kind=ek.CONTAINS,
            description="Resource set contains device",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.AUTH_SERVER,
            kind=ek.CONTAINS,
            description="Resource set contains auth server",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.IDP,
            kind=ek.CONTAINS,
            description="Resource set contains IDP",
            traversable=True,
        ),
        EdgeDef(
            start=nk.RESOURCE_SET,
            end=nk.POLICY,
            kind=ek.CONTAINS,
            description="Resource set contains policy",
            traversable=True,
        ),
    ],
)
class Resource(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
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

    def _yield_edge(self, target_id: str):
        yield Edge(
            kind=ek.RESOURCE_SET_CONTAINS,
            start=EdgePath(value=self.resource_set_id, match_by="id"),
            end=EdgePath(value=target_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        resource_type = self.resource_type
        resource_id = self.resource_id
        if resource_id:
            yield from self._yield_edge(resource_id)

        all_resource = {
            "users": self._lookup.all_users,
            "groups": self._lookup.all_groups,
            "apps": self._lookup.all_applications,
            "devices": self._lookup.all_devices,
            "authorizationServers": self._lookup.all_auth_servers,
            "idps": self._lookup.all_identity_providers,
            "policies": self._lookup.all_policies,
        }

        if all_resource.get(resource_type):
            for (resource_id,) in all_resource[resource_type]():
                yield from self._yield_edge(resource_id)
