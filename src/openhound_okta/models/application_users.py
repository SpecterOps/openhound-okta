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
    username: str | None = Field(default=None, alias="userName")


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
    login: str | None = None
    state: str | None = None
    dn: str | None = None
    manager_dn: str | None = Field(default=None, alias="managerDn")
    cn: str | None = None
    object_sid: str | None = Field(default=None, alias="objectSid")
    sam_account_name: str | None = Field(default=None, alias="samAccountName")
    initial_status: str | None = Field(default=None, alias="initialStatus")


@app.asset(
    description="Okta application users",
    edges=[
        EdgeDef(
            kind=ek.APP_ASSIGNMENT,
            start=nk.USER,
            end=nk.APPLICATION,
            traversable=False,
            description="User is assigned to an application",
        ),
        EdgeDef(
            kind=ek.USER_PULL,
            start=nk.APPLICATION,
            end=nk.USER,
            traversable=True,
            description="User is pulled form an external application",
        ),
        EdgeDef(
            kind=ek.USER_PUSH,
            start=nk.USER,
            end=nk.APPLICATION,
            traversable=False,
            description="User is pushed to an application",
        ),
        EdgeDef(
            kind=ek.USER_SYNC,
            start=nk.USER,
            end=nk.AD_USER,
            traversable=False,
            description="User is synced to an Active Directory user",
        ),
        EdgeDef(
            kind=ek.USER_SYNC,
            start=nk.AD_USER,
            end=nk.USER,
            traversable=False,
            description="User is synced from an Active Directory user",
        ),
        # TODO: Creat new edge kind for AD sync
        EdgeDef(
            kind=ek.PASSWORD_SYNC,
            start=nk.AD_USER,
            end=nk.USER,
            traversable=True,
            description="Credentials are synced between AD and Okta users",
        ),
        EdgeDef(
            kind=ek.PASSWORD_SYNC,
            start=nk.USER,
            end=nk.USER,
            traversable=True,
            description="Credentials are synced between okta orgs",
        ),
    ],
)
class ApplicationUser(BaseAsset):
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
    external_id: str | None = Field(default=None, alias="externalId")

    # Additional
    app_id: str
    app_features: list[str] = Field(default_factory=list)
    app_name: str
    app_label: str
    app_settings: dict | None = None

    # "USER" = directly assigned and "GROUP" = assigned via group membership.
    scope: str = Field(default="USER")
    sync_state: str | None = Field(default=None, alias="syncState")

    @property
    def as_node(self):
        return None

    @property
    def _read_password_updates_edge(self):
        if "PUSH_PASSWORD_UPDATES" in self.app_features:
            yield Edge(
                kind=ek.READ_PASSWORD_UPDATES,
                start=EdgePath(value=self.app_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _app_assignment_edge(self):
        if self.scope == "USER":
            yield Edge(
                kind=ek.APP_ASSIGNMENT,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _user_push_poll_edges(self):
        # TODO: Verify this logic
        if self.sync_state == "SYNCHRONIZED":
            if self.scope == "USER":
                yield Edge(
                    kind=ek.USER_PULL,
                    start=EdgePath(value=self.app_id, match_by="id"),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )
            else:
                yield Edge(
                    kind=ek.USER_PUSH,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=self.app_id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _password_sync_edge(self):
        if self.sync_state == "SYNCHRONIZED" and self.app_name == "active_directory":
            if self.scope == "USER" and self.profile.object_sid:
                # app_domain = self.app_settings.get("domain")
                # ad_domain = app_domain if app_domain else self.app_label
                # TODO: Determine the matching between okta user and AD user
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.profile.object_sid, match_by="id"),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

                # TODO: Ditto, verify matching between okta user and AD user
                if "OUTBOUND_DEL_AUTH" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.profile.object_sid, match_by="id"),
                        end=EdgePath(value=self.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                # Outboundsync, ie. OktaUser--Okta_UserSync->AD????
                # TODO: Determine the matching between okta user and AD user
                # is this really based on a group/non-user?
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=self.profile.object_sid, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )
                # TODO: Ditto, verify matching between okta user and AD user
                if "PUSH_PASSWORD_UPDATES" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.id, match_by="id"),
                        end=EdgePath(value=self.profile.object_sid, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _okta_org2org_edges(self):
        # TODO: Verify and check SCIM
        if self.app_name == "okta_org2org":
            if self.scope == "USER":
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.external_id, match_by="id"),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

            else:
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=self.external_id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

                if "PUSH_PASSWORD_UPDATES" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.id, match_by="id"),
                        end=EdgePath(value=self.external_id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def edges(self):
        yield from self._app_assignment_edge
        yield from self._read_password_updates_edge
        yield from self._user_push_poll_edges
        yield from self._password_sync_edge
        yield from self._okta_org2org_edges
