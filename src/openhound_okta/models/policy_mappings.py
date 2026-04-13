from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, Field
from pydantic import ConfigDict

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


class ApplicationLink(BaseModel):
    href: str


class Link(BaseModel):
    application: ApplicationLink | None = None


@app.asset(
    description="Okta policy asset mapping",
    edges=[
        EdgeDef(
            start=nk.POLICY,
            end=nk.APPLICATION,
            kind=ek.POLICY_MAPPING,
            description="Okta policy maps to application",
            traversable=False,
        ),
    ],
)
class PolicyMapping(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    links: Link = Field(alias="_links")

    # Additional
    policy_id: str

    @property
    def app_id(self):
        return self.links.application.href.split("/apps/")[1]

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        if self.links.application:
            yield Edge(
                kind=ek.POLICY_MAPPING,
                start=EdgePath(value=self.policy_id, match_by="id"),
                end=EdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
