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


@dataclass
class ApiServiceProperties(OktaNodeProperties):
    """Properties for the Okta_ApiServiceIntegration node"""

    okta_domain: str
    app_type: str
    created_at: datetime
    oauth_scopes: list[str] | None = None


@app.asset(
    description="Okta API service integration asset",
    node=NodeDef(
        icon="robot",
        kind=nk.INTEGRATION,
        description="Okta API service integration node",
        properties=ApiServiceProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.INTEGRATION,
            kind=ek.CONTAINS,
            description="Organization contains API service integration",
            traversable=True,
        ),
        EdgeDef(
            start=nk.USER,
            end=nk.INTEGRATION,
            kind=ek.CREATOR_OF,
            description="User created the API service integration",
            traversable=False,
        ),
    ],
)
class ApiService(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    type: str
    name: str
    created_at: datetime = Field(alias="createdAt")
    created_by: str = Field(alias="createdBy")
    config_guide_url: str | None = Field(alias="configGuideUrl", default=None)
    granted_scopes: list[str] = Field(alias="grantedScopes")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.INTEGRATION],
            properties=ApiServiceProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.name,
                okta_domain=self._extras["tenant"],
                app_type=self.type,
                created_at=self.created_at,
                oauth_scopes=self.granted_scopes,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _contains_edges(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=OktaOwnedEdgePath(value=self._lookup.org_id(), match_by="id"),
            end=OktaOwnedEdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _creator_of_edges(self):
        if self.created_by:
            yield Edge(
                kind=ek.CREATOR_OF,
                start=OktaOwnedEdgePath(value=self.created_by, match_by="id"),
                end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def edges(self):
        yield from self._contains_edges
        yield from self._creator_of_edges
