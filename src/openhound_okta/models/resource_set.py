from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaOwnedEdgePath, OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app

WORKFLOWS_RESOURCE_SET_ID = "WORKFLOWS_IAM_POLICY"


def resource_set_node_id(resource_set_id: str, tenant_domain: str | None) -> str:
    """Return the OktaHound-compatible graph ID for a resource set."""
    if resource_set_id == WORKFLOWS_RESOURCE_SET_ID and tenant_domain:
        return f"{resource_set_id}@{tenant_domain}"
    return resource_set_id


@dataclass
class ResourceSetProperties(OktaNodeProperties):
    """Properties for the Okta_ResourceSet node"""

    okta_domain: str
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
            traversable=True,
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
    def node_id(self) -> str:
        return resource_set_node_id(
            self.id,
            getattr(self, "_extras", {}).get("tenant"),
        )

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.RESOURCE_SET],
            properties=ResourceSetProperties(
                tenant=self._lookup.org_id(),
                id=self.node_id,
                name=self.label,
                displayname=self.label,
                okta_domain=self._extras["tenant"],
                created=self.created,
                description=self.description,
                last_updated=self.last_updated,
                environmentid=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=OktaOwnedEdgePath(value=self._lookup.org_id(), match_by="id"),
            end=OktaOwnedEdgePath(value=self.node_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
