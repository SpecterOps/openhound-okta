from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


class Profile(BaseModel):
    last_name: str | None = Field(alias="lastName", default=None)
    first_name: str | None = Field(alias="firstName", default=None)
    email: str | None = None
    subject_name_id: str | None = Field(alias="subjectNameId", default=None)


@app.asset(
    description="Okta identity provider asset",
    edges=[
        EdgeDef(
            start=nk.IDP,
            end=nk.USER,
            kind=ek.IDENTITY_PROVIDER_FOR,
            description="Identity provider manages user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ORG,
            end=nk.USER,
            kind=ek.INBOUND_SSO,
            description="User identity via SSO",
            traversable=False,
        ),
    ],
)
class IDPUser(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    external_id: str = Field(alias="externalId")
    created: datetime | None = None
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)
    profile: Profile

    # Additional
    idp_id: str
    idp_type: str
    idp_name: str
    idp_url: str | None = None

    @property
    def as_node(self):
        return None

    @property
    def _inbound_sso_edge(self):
        if self.idp_type == "SAML2" and "microsoftonline.com" in self.idp_url:
            yield Edge(
                kind=ek.INBOUND_SSO,
                start=EdgePath(value=self.external_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _identity_provider_for_edge(self):
        yield Edge(
            kind=ek.IDENTITY_PROVIDER_FOR,
            start=EdgePath(value=self.idp_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def edges(self):
        yield from self._identity_provider_for_edge
        yield from self._inbound_sso_edge
