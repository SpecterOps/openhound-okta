from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class AuthServerProperties(OktaNodeProperties):
    """Properties for the Okta_AuthorizationServer node"""

    name: str
    status: str
    created: datetime
    description: str | None = None
    issuer: str | None = None
    issuer_mode: str | None = None
    audiences: list[str] | None = None
    last_updated: datetime | None = None


@app.asset(
    description="Okta authorization server asset",
    node=NodeDef(
        icon="certificate",
        kind=nk.AUTH_SERVER,
        description="Okta authorization server node",
        properties=AuthServerProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.AUTH_SERVER,
            kind=ek.CONTAINS,
            description="Organization contains authorization server",
            traversable=False,
        )
    ],
)
class AuthServer(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str | None = None
    audiences: list[str] | None = None
    issuer: str
    issuer_mode: str | None = Field(default=None, alias="issuerMode")
    status: str
    created: datetime
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    credentials: dict | None = None
    default: bool | None = None

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.AUTH_SERVER],
            properties=AuthServerProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.name,
                displayname=self.name,
                status=self.status,
                created=self.created,
                description=self.description,
                issuer=self.issuer,
                issuer_mode=self.issuer_mode,
                audiences=self.audiences,
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
