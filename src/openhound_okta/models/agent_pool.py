from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class AgentPoolProperties(OktaNodeProperties):
    """Properties for Okta agent pool"""

    name: str
    type: str
    operational_status: str


class Agent(BaseModel):
    id: str
    state: str | None = None
    message: str | None = None
    indicator: str | None = None
    name: str
    version: str
    upgrade_required: bool | None = Field(alias="upgradeRequired", default=None)
    active: bool | None = None
    support_auto_update: bool | None = Field(alias="supportAutoUpdate", default=None)
    error_state: bool | None = Field(alias="errorState", default=None)
    is_hidden: bool = Field(alias="isHidden")
    is_latest_gaed_version: bool = Field(alias="isLatestGAedVersion")
    last_connection: datetime | None = Field(alias="lastConnection", default=None)
    operational_status: str | None = Field(alias="operationalStatus", default=None)
    pool_id: str = Field(alias="poolId")
    update_message: str | None = Field(alias="updateMessage", default=None)


@app.asset(
    description="Okta agent pool asset",
    node=NodeDef(
        icon="gears",
        kind=nk.AGENT_POOL,
        description="Okta agent pool node",
        properties=AgentPoolProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.AGENT_POOL,
            kind=ek.CONTAINS,
            description="Organization contains agent pool",
            traversable=False,
        ),
        EdgeDef(
            start=nk.AGENT_POOL,
            end=nk.AGENT,
            kind=ek.AGENT_POOL_FOR,
            description="Agent pool for okta agent",
            traversable=False,
        ),
    ],
)
class AgentPool(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    name: str
    type: str
    disrupted_agents: int = Field(alias="disruptedAgents")
    inactive_agents: int = Field(alias="inactiveAgents")
    operational_status: str = Field(alias="operationalStatus")
    agents: list[Agent] | None = Field(default=list)

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.AGENT_POOL],
            properties=AgentPoolProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.name,
                displayname=self.name,
                type=self.type,
                operational_status=self.operational_status,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _agent_pool_for_edges(self):
        for agent in self.agents:
            yield Edge(
                kind=ek.AGENT_POOL_FOR,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=agent.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def edges(self):
        yield from self._contains_edge
        yield from self._agent_pool_for_edges
