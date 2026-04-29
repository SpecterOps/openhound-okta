from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class PolicyProperties(OktaNodeProperties):
    """Properties for the Okta_Policy node"""

    name: str
    policy_type: str
    created: datetime
    priority: int | None = None
    system: bool = False
    description: str | None = None


@app.asset(
    description="Okta policy asset",
    node=NodeDef(
        icon="shield",
        kind=nk.POLICY,
        description="Okta policy node",
        properties=PolicyProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.POLICY,
            kind=ek.CONTAINS,
            description="Organization contains policy",
            traversable=False,
        ),
    ],
)
class Policy(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    name: str
    type: str
    priority: int | None = None
    system: bool | None = None
    description: str | None = None
    created: datetime
    condition: str | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.POLICY],
            properties=PolicyProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.name,
                policy_type=self.type,
                created=self.created,
                priority=self.priority,
                system=self.system or False,
                description=self.description,
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
