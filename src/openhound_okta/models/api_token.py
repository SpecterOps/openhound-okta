from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class ApiTokenProperties(OktaNodeProperties):
    """Properties for the Okta_ApiToken node"""

    user_id: str
    created: datetime
    client_name: str | None = None
    expires_at: str | None = None
    last_updated: datetime | None = None


@app.asset(
    description="Okta API token asset",
    node=NodeDef(
        icon="key",
        kind=nk.API_TOKEN,
        description="Okta API token node",
        properties=ApiTokenProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.API_TOKEN,
            end=nk.USER,
            kind=ek.API_TOKEN_FOR,
            description="API token is owned by a user",
            traversable=True,
        )
    ],
)
class ApiToken(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    user_id: str = Field(alias="userId")
    token_window: str = Field(alias="tokenWindow")
    network: dict | None = None
    id: str
    client_name: str = Field(alias="clientName")
    expires_at: str = Field(alias="expiresAt")
    created: datetime
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.API_TOKEN],
            properties=ApiTokenProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.name,
                displayname=self.name,
                user_id=self.user_id,
                created=self.created,
                client_name=self.client_name,
                expires_at=self.expires_at,
                last_updated=self.last_updated,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.API_TOKEN_FOR,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.user_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
