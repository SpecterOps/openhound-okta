from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgePath,
    EdgeProperties,
    ConditionalEdgePath,
    PropertyMatch,
)
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class AgentProperties(OktaNodeProperties):
    """Properties for Okta agent"""

    name: str
    operational_status: str
    type: str
    version: str


@app.asset(
    description="Okta agent pool asset",
    node=NodeDef(
        icon="gear",
        kind=nk.AGENT,
        description="Okta agent node",
        properties=AgentProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.AGENT,
            end=nk.AGENT_POOL,
            kind=ek.AGENT_MEMBER_OF,
            description="Agent belongs to agent pool",
            traversable=False,
        ),
        EdgeDef(
            start=nk.AD_USER,
            end=nk.AGENT,
            kind=ek.HOSTS_AGENT,
            description="Computer hosts okta agent",
            traversable=False,
        ),
    ],
)
class Agent(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

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
    is_latest_gaed_version: bool | None = Field(
        alias="isLatestGAedVersion", default=None
    )
    last_connection: datetime | None = Field(alias="lastConnection", default=None)
    operational_status: str | None = Field(alias="operationalStatus", default=None)
    pool_id: str = Field(alias="poolId")
    update_message: str | None = Field(alias="updateMessage", default=None)

    # Additional
    agent_pool_name: str | None = None
    agent_type: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.AGENT],
            properties=AgentProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.name,
                type=self.agent_type,
                operational_status=self.operational_status,
                version=self.version,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _hosts_agent_edge(self):
        if self.agent_type == "AD":
            # The agent name has a prefix that needs to be stripped before matching is possible
            agent_name_split = self.name.split("-")
            agent_name = '-'.join(agent_name_split[1:])
            agent_match = f"{agent_name.upper()}-{self.agent_pool_name.upper()}"
            match_with = PropertyMatch(
                key="name", value=agent_match
            )
            yield Edge(
                start=ConditionalEdgePath(
                    kind="Computer", property_matchers=[match_with]
                ),
                end=EdgePath(value=self.id, match_by="id"),
                kind=ek.HOSTS_AGENT,
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _agent_member_of_edge(self):
        yield Edge(
            kind=ek.AGENT_MEMBER_OF,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.pool_id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def edges(self):
        yield from self._agent_member_of_edge
        yield from self._hosts_agent_edge
