from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaOwnedEdgePath
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app

# Provider, Credentials and Profile describe the user object that
# GET /groups/{groupId}/users returns for each member. They are kept here to
# document the upstream shape, but the group_memberships transformer does NOT
# collect them: a membership row is one per member per group, so any payload
# carried on it is multiplied by millions in a large tenant, and the full user
# record is already collected by the users resource. Only profile.login is
# kept, flattened to GroupMembership.login.


class Provider(BaseModel):
    """Credential provider of a member. Not collected."""

    name: str
    type: str | None = None


class Credentials(BaseModel):
    """Credentials of a member. Not collected."""

    model_config = ConfigDict(populate_by_name=True)
    provider: Provider | None = None


class Profile(BaseModel):
    """Profile of a member. Not collected; only login is kept, flattened."""

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
    """Membership of an Okta user in an Okta group.

    Only the keys the graph and lookups consume are collected; the member's
    user record itself lives in the users table.

    Attributes:
        id: Okta user ID of the member.
        login: Okta login of the member, flattened from profile.login.
        group_id: Okta group ID the user belongs to.
        group_has_admin_privilege: Whether the group carries an admin role, so
            the chained admin_group_member_factors transformer can select
            admin-group members without paginating the member list again.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    login: str | None = None
    group_id: str
    group_has_admin_privilege: bool = False

    # Remaining attributes of the upstream member object. Not collected; see
    # the module comment above.
    # created: datetime | None = None
    # activated: datetime | None = None
    # last_login: datetime | None = Field(default=None, alias="lastLogin")
    # last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    # password_changed: datetime | None = Field(default=None, alias="passwordChanged")
    # profile: Profile
    # status: str | None = None
    # realm_id: str | None = Field(default=None, alias="realmId")
    # credentials: Credentials | None = None

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        yield Edge(
            kind=ek.MEMBER_OF,
            start=OktaOwnedEdgePath(value=self.id, match_by="id"),
            end=OktaOwnedEdgePath(value=self.group_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
