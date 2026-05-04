from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import nodes as nk
from openhound_okta.main import app


@dataclass
class OrganizationProperties(OktaNodeProperties):
    """Properties for the Okta_Organization node"""

    subdomain: str
    status: str
    created: datetime
    last_updated: datetime | None = None
    company_name: str | None = None
    website: str | None = None
    collected: bool = True


@app.asset(
    description="Okta organization asset",
    node=NodeDef(
        icon="globe",
        kind=nk.ORG,
        description="Okta organization node",
        properties=OrganizationProperties,
    ),
)
class Organization(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    subdomain: str
    status: str
    expires_at: str | None = Field(default=None, alias="expiresAt")
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime
    website: str | None = None
    company_name: str | None = Field(default=None, alias="companyName")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.ORG],
            properties=OrganizationProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.company_name or self.subdomain,
                displayname=self.company_name or self.subdomain,
                subdomain=self.subdomain,
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                company_name=self.company_name,
                website=self.website,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        return []
