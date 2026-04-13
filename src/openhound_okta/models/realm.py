from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class RealmProperties(OktaNodeProperties):
    """Properties for the Okta_Realm node"""

    created: datetime
    is_default: bool = False
    realm_type: str | None = None
    domains: list[str] | None = None
    last_updated: datetime | None = None


class RealmProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str
    realm_type: str | None = Field(default=None, alias="realmType")
    domains: list[str] | None = None


@app.asset(
    description="Okta realm asset",
    node=NodeDef(
        icon="building",
        kind=nk.REALM,
        description="Okta realm node",
        properties=RealmProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.REALM,
            kind=ek.CONTAINS,
            description="Organization contains realm",
            traversable=False,
        ),
    ],
)
class Realm(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    created: datetime
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    is_default: bool = Field(alias="isDefault")
    profile: RealmProfile

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.REALM],
            properties=RealmProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.profile.name,
                displayname=self.profile.name,
                created=self.created,
                is_default=self.is_default,
                realm_type=self.profile.realm_type,
                domains=self.profile.domains,
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
