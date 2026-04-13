from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class ResourceSetProperties(OktaNodeProperties):
    """Properties for the Okta_ResourceSet node"""

    label: str
    created: datetime
    description: str | None = None
    last_updated: datetime | None = None


@app.asset(
    description="Okta resource set asset",
    node=NodeDef(
        icon="folder",
        kind=nk.RESOURCE_SET,
        description="Okta resource set node",
        properties=ResourceSetProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.RESOURCE_SET,
            kind=ek.CONTAINS,
            description="Organization contains resource set",
            traversable=False,
        )
    ],
)
class ResourceSet(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    label: str
    description: str | None = None
    created: datetime | None = None
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    links: dict | None = Field(default=None, alias="_links")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.RESOURCE_SET],
            properties=ResourceSetProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.label,
                displayname=self.label,
                label=self.label,
                created=self.created,
                description=self.description,
                last_updated=self.last_updated,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
