from dataclasses import dataclass
from dataclasses import field
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class SecretProperties(OktaNodeProperties):
    """Properties for Okta_ClientSecret node"""

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
    description="Okta application client secrets",
    node=NodeDef(
        icon="key",
        kind=nk.CLIENT_SECRET,
        description="Okta client secret configured for application",
        properties=SecretProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.CLIENT_SECRET,
            end=nk.APPLICATION,
            kind=ek.SECRET_OF,
            description="Client secret belongs to application",
            traversable=True,
        )
    ],
)
class ApplicationSecrets(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    secret_hash: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime | None = None
    status: str

    # Additional
    app_id: str
    app_name: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.CLIENT_SECRET],
            properties=SecretProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                name=self.secret_hash,
                displayname=self.secret_hash,
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
            kind=ek.SECRET_OF,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.app_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
