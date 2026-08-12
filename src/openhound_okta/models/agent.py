from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgeProperties,
    ConditionalEdgePath,
    PropertyMatch,
)
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaOwnedEdgePath, OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.agent_pool import agent_pool_graph_id


@dataclass
class AgentProperties(OktaNodeProperties):
    """Properties for Okta agent"""

    name: str
    okta_domain: str
    operational_status: str
    type: str | None
    version: str
    pool_id: str
    pool_name: str | None = None
    update_status: str | None = None
    last_connection: datetime | None = None


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
            traversable=True,
        ),
        EdgeDef(
            start=nk.AD_COMPUTER,
            end=nk.AGENT,
            kind=ek.HOSTS_AGENT,
            description="Computer hosts okta agent",
            traversable=True,
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
    is_hidden: bool | None = Field(alias="isHidden", default=None)
    is_latest_gaed_version: bool | None = Field(
        alias="isLatestGAedVersion", default=None
    )
    last_connection: datetime | None = Field(alias="lastConnection", default=None)
    operational_status: str | None = Field(alias="operationalStatus", default=None)
    pool_id: str = Field(alias="poolId")
    update_status: str | None = Field(alias="updateStatus", default=None)
    update_message: str | None = Field(alias="updateMessage", default=None)

    # Additional
    agent_pool_name: str | None = None
    agent_type: str
    type: str | None = None

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
                okta_domain=self._extras["tenant"],
                type=self.type,
                operational_status=self.operational_status,
                version=self.version,
                pool_id=self.pool_id,
                pool_name=self.agent_pool_name,
                update_status=self.update_status,
                last_connection=self.last_connection,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _hosts_agent_edge(self):
        if self.agent_type == "AD" and self.agent_pool_name:
            matchers = [
                PropertyMatch(key="samaccountname", value=f"{self.name.upper()}$"),
                PropertyMatch(key="domain", value=self.agent_pool_name.upper()),
            ]
            yield Edge(
                start=ConditionalEdgePath(
                    kind=nk.AD_COMPUTER, property_matchers=matchers
                ),
                end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                kind=ek.HOSTS_AGENT,
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _agent_member_of_edge(self):
        yield Edge(
            kind=ek.AGENT_MEMBER_OF,
            start=OktaOwnedEdgePath(value=self.id, match_by="id"),
            end=OktaOwnedEdgePath(
                value=agent_pool_graph_id(self.pool_id), match_by="id"
            ),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        yield from self._agent_member_of_edge
        yield from self._hosts_agent_edge
