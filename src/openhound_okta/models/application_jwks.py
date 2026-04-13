from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app

from dataclasses import field


@dataclass
class JWKProperties(OktaNodeProperties):
    """Properties for the Okta_JWK node"""

    id: str = field(
        metadata={"description": "The unique identifier for the JSON Web Key"}
    )
    status: str = field(
        metadata={"description": "The active/inactive state of the JSON Web Key"}
    )
    last_updated: datetime | None = field(
        default=None,
        metadata={"description": "The last time the JSON Web Key was updated"},
    )
    created: datetime | None = field(
        default=None, metadata={"description": "The time the JSON Web Key was created"}
    )


@app.asset(
    description="Okta application JSON Web Keys",
    node=NodeDef(
        icon="key",
        kind=nk.JWK,
        description="Okta JSON Web Key configured by application",
        properties=JWKProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.JWK,
            end=nk.APPLICATION,
            kind=ek.KEY_OF,
            description="JSON Web Key belongs to application",
            traversable=True,
        )
    ],
)
class ApplicationJWKS(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    kid: str
    use: str
    n: str
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime | None = None

    # Additional
    app_id: str
    app_name: str

    @property
    def display_name(self) -> str:
        return f"JWK_{self.app_name}_{self.id}"

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.JWK],
            properties=JWKProperties(
                tenant=self._lookup.org_id(),
                name=self.display_name,
                displayname=self.display_name,
                id=self.id,
                status=self.status,
                last_updated=self.last_updated,
                created=self.created,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.KEY_OF,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.app_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
