from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


class Provider(BaseModel):
    name: str
    type: str


class Credentials(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    provider: Provider | None = None


class Profile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    email: str | None = None
    first_name: str | None = Field(default=None, alias="firstName")
    last_name: str | None = Field(default=None, alias="lastName")
    department: str | None = None
    city: str | None = None
    country_code: str | None = Field(default=None, alias="countryCode")
    employee_number: str | None = Field(default=None, alias="employeeNumber")
    division: str | None = None
    organization: str | None = None
    title: str | None = None
    user_type: str | None = Field(default=None, alias="userType")
    manager_id: str | None = Field(default=None, alias="managerId")
    login: str
    state: str | None = None


@app.asset(
    description="Okta user membership asset",
    edges=[
        EdgeDef(
            kind=ek.MEMBER_OF,
            start=nk.USER,
            end=nk.GROUP,
            description="User is a member of a group",
        )
    ],
)
class GroupMembership(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    created: datetime
    activated: datetime | None = None
    last_login: datetime | None = Field(default=None, alias="lastLogin")
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    password_changed: datetime | None = Field(default=None, alias="passwordChanged")
    profile: Profile
    status: str
    realm_id: str | None = Field(default=None, alias="realmId")
    credentials: Credentials | None = None

    # Additional
    group_id: str

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        yield Edge(
            kind=ek.MEMBER_OF,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.group_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
