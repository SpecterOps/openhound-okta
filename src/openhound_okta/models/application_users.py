from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.hybrid_auth import (
    HybridAuthEdgeProperties,
    hybrid_target_edge_path,
    hybrid_user_sign_on_edge_kind,
    hybrid_user_target,
)
from openhound_okta.models.saml import (
    SamlMatchValuesEdgeProperties,
    saml_application_identity_evidence,
    saml_match_source,
    saml_provider_id,
)

# To ignore system apps optionally
SYSTEM_APPS = [
    "okta_oin_submission_tester_app",  # Okta OIN Submission Tester
    "okta_access_requests_resource_catalog",  # Okta Identity Governance
    "okta_enduser",  # Okta Dashboard
    "okta_browser_plugin",  # Okta Browser Plugin
    "active_directory",  # Active Directory, for which there are sync edges
    "ldap_interface"  # LDAP Interface, similar to AD
]

IGNORED_OUTBOUND_SYNC_APPS = {
    "okta_flow_sso",  # Okta Workflows
    "okta_atspoke_sso",  # Okta Access Requests
}

ACTIVE_DIRECTORY_APP = "active_directory"
LDAP_INTERFACE_APP = "ldap_interface"
OKTA_ORG2ORG_APP = "okta_org2org"


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
            traversable=False,
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
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.USER,
            traversable=True,
            description="User signs on to another Okta organization",
        ),
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.JAMF_ACCOUNT,
            traversable=True,
            description="User signs on to a Jamf account",
        ),
        EdgeDef(
            kind=ek.SWA,
            start=nk.USER,
            end=nk.JAMF_ACCOUNT,
            traversable=False,
            description="User stores credentials for a Jamf account",
        ),
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.GITHUB_USER,
            traversable=True,
            description="User signs on to a GitHub account",
        ),
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.ONE_PASSWORD_USER,
            traversable=True,
            description="User signs on to a 1Password account",
        ),
        EdgeDef(
            kind=ek.SWA,
            start=nk.USER,
            end=nk.ONE_PASSWORD_USER,
            traversable=False,
            description="User stores credentials for a 1Password account",
        ),
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.SNOWFLAKE_USER,
            traversable=True,
            description="User signs on to a Snowflake account",
        ),
        EdgeDef(
            kind=ek.OUTBOUND_SSO,
            start=nk.USER,
            end=nk.AZ_USER,
            traversable=True,
            description="User signs on to an Entra account",
        ),
        EdgeDef(
            kind=ek.SWA,
            start=nk.USER,
            end=nk.AZ_USER,
            traversable=False,
            description="User stores credentials for an Entra account",
        ),
        EdgeDef(
            kind=ek.SAML_ELIGIBLE_FOR,
            start=nk.USER,
            end=nk.SAML_FEDERATION_PROVIDER,
            traversable=False,
            description="Okta user is eligible for a normalized SAML provider",
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
    app_sign_on_mode: str | None = None
    app_subject_name_id_template: str | None = None
    app_subject_name_id_format: str | None = None
    app_user_name_template: str | None = None

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
        # Note: Check if we want to filter default assignments (factual to the environment)
        # or filter out default assignments (to clean up the graph)
        if self.scope == "USER":
            yield Edge(
                kind=ek.APP_ASSIGNMENT,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _target_user_name(self) -> str | None:
        return self.credentials.username if self.credentials else None

    @property
    def _hybrid_sign_on_edges(self):
        edge_kind = hybrid_user_sign_on_edge_kind(self.app_sign_on_mode)
        if edge_kind is None:
            return

        target = hybrid_user_target(
            self.app_name,
            self.app_settings,
            target_user_name=self._target_user_name,
            external_id=self.external_id,
        )
        if target is None:
            return

        yield Edge(
            kind=edge_kind,
            start=EdgePath(value=self.id, match_by="id"),
            end=hybrid_target_edge_path(target),
            properties=HybridAuthEdgeProperties(
                traversable=edge_kind == ek.OUTBOUND_SSO,
                mode=self.app_sign_on_mode,
            ),
        )

    @property
    def _inbound_user_sync_enabled(self) -> bool:
        return "PROFILE_MASTERING" in self.app_features

    @property
    def _is_inbound_sync(self) -> bool:
        if self.app_name == ACTIVE_DIRECTORY_APP:
            return self.scope == "USER"

        if self.app_name == LDAP_INTERFACE_APP:
            return True

        if self.scope == "GROUP":
            return False

        if self.app_name == OKTA_ORG2ORG_APP:
            return (
                "initial_status" not in self.profile.model_fields_set
                and self._inbound_user_sync_enabled
            )

        return self._inbound_user_sync_enabled

    @property
    def _user_push_pull_edges(self):
        if self.sync_state != "SYNCHRONIZED":
            return

        if self._is_inbound_sync:
            yield Edge(
                kind=ek.USER_PULL,
                start=EdgePath(value=self.app_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
        elif self.app_name not in IGNORED_OUTBOUND_SYNC_APPS:
            yield Edge(
                kind=ek.USER_PUSH,
                start=EdgePath(value=self.id, match_by="id"),
                end=EdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _password_sync_edge(self):
        if (
            self.sync_state == "SYNCHRONIZED"
            and self.app_name == ACTIVE_DIRECTORY_APP
            and self.profile.object_sid
        ):
            if self._is_inbound_sync:
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.profile.object_sid, match_by="id"),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

                if "OUTBOUND_DEL_AUTH" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.profile.object_sid, match_by="id"),
                        end=EdgePath(value=self.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=self.profile.object_sid, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )
                if "PUSH_PASSWORD_UPDATES" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.id, match_by="id"),
                        end=EdgePath(value=self.profile.object_sid, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _okta_org2org_edges(self):
        if self.app_name == OKTA_ORG2ORG_APP:
            if self._is_inbound_sync:
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
    def _saml_eligible_for_edges(self):
        if self.app_sign_on_mode != "SAML_2_0":
            return
        if self.status not in {"ACTIVE", "PROVISIONED"}:
            return
        evidence = saml_application_identity_evidence(self)
        if not evidence["match_values"]:
            return
        yield Edge(
            kind=ek.SAML_ELIGIBLE_FOR,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=saml_provider_id(self.app_id), match_by="id"),
            properties=SamlMatchValuesEdgeProperties(
                traversable=False,
                match_values=evidence["match_values"],
                email_match_values=evidence["email_match_values"],
                scoped_exact_match_values=evidence["scoped_exact_match_values"],
                source_property=saml_match_source(
                    self.app_subject_name_id_template or self.app_user_name_template
                ),
            ),
        )

    @property
    def edges(self):
        yield from self._app_assignment_edge
        yield from self._read_password_updates_edge
        yield from self._user_push_pull_edges
        yield from self._password_sync_edge
        yield from self._okta_org2org_edges
        yield from self._hybrid_sign_on_edges
        yield from self._saml_eligible_for_edges
