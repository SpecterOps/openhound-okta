from collections.abc import Iterator
from typing import Any, Final

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.app_names import AppName
from openhound_okta.graph import OktaOwnedEdgePath
from openhound_okta.kinds import edges as ek
from openhound_okta.kinds import nodes as nk
from openhound_okta.main import app
from openhound_okta.models.hybrid_auth import (
    HybridAuthEdgeProperties,
    hybrid_target_edge_path,
    hybrid_user_sign_on_edge_kind,
    hybrid_user_target,
)
from openhound_okta.models.saml import (
    SamlMatchValuesEdgeProperties,
    SamlResolutionValueEdgeProperties,
    saml_application_assertion_evidence,
    saml_match_source,
    saml_provider_id,
)

# To ignore system apps optionally
SYSTEM_APPS: Final[frozenset[str]] = frozenset(
    {
        "okta_oin_submission_tester_app",  # Okta OIN Submission Tester
        "okta_access_requests_resource_catalog",  # Okta Identity Governance
        "okta_enduser",  # Okta Dashboard
        "okta_browser_plugin",  # Okta Browser Plugin
        "active_directory",  # Active Directory, for which there are sync edges
        "ldap_interface",  # LDAP Interface, similar to AD
    }
)

IGNORED_OUTBOUND_SYNC_APPS: Final[frozenset[str]] = frozenset(
    {
        "okta_flow_sso",  # Okta Workflows
        "okta_atspoke_sso",  # Okta Access Requests
    }
)

# Apps whose assigned users are always collected, even when
# `limit_app_user_collection` is enabled: every app type the collector recognizes, i.e.
# hybrid-auth / sync apps, the OIN SAML apps whose assertions are fully normalized, and
# apps commonly assigned in customer tenants.
ALWAYS_COLLECTED_APP_USERS: Final[frozenset[str]] = frozenset(AppName)


# Application user rows are one per assignment, so every attribute kept on
# them is multiplied by millions in a large tenant. The application_users
# transformer therefore skips the assignment keys (APPLICATION_USER_ITEM_SKIPPED_KEYS)
# and profile attributes (APPLICATION_USER_PROFILE_SKIPPED_KEYS) that nothing
# reads. Attributes that are NOT collected stay in the models below, commented
# out, to document the upstream shape.

# Keys of a GET /apps/{appId}/users item skipped at collection time: nothing
# reads the timestamps, links or embedded user copies, and dropping them keeps
# the largest collected table narrow. The profile is trimmed separately.
APPLICATION_USER_ITEM_SKIPPED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "created",
        "lastUpdated",
        "passwordChanged",
        "statusChanged",
        "lastSync",
        "_links",
        "_embedded",
    }
)

# Application user profile attributes skipped at collection time. Nothing
# reads them, and the Entra licence assignments are large. Every other
# attribute is kept because SAML claim mappings may reference it; department,
# city and country are plausible appuser.* claim sources and so are kept too.
# TODO: Instead of guessing, keep only the attributes the application's own
# SAML attribute statements and NameID/user name templates reference, per app.
APPLICATION_USER_PROFILE_SKIPPED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "licenses",  # Assigned Office 365 licenses
        "division",
        "organization",
        "costCenter",
        "title",
        "managerId",
        "managerDn",
        "honorificPrefix",
        "honorificSuffix",
        "middleName",
        "nickName",
        "primaryPhone",
        "primaryPhoneType",
        "addressType",
        "streetAddress",
        "locality",
        "region",
        "state",
        "postalCode",
        "countryCode",
        "locale",
        "preferredLanguage",
        "timezone",
    }
)


class Credentials(BaseModel):
    """Application credentials of the assignment.

    Attributes:
        username: User name in the application; the hybrid-auth and SAML
            edges match external accounts on it.
    """

    model_config = ConfigDict(populate_by_name=True)
    username: str | None = Field(default=None, alias="userName")


class Profile(BaseModel):
    """Application-specific user profile.

    extra="allow" keeps attributes beyond the declared ones because SAML claim
    mappings may reference any of them. Attributes listed in
    APPLICATION_USER_PROFILE_SKIPPED_KEYS are not collected and stay commented
    out below.

    Attributes:
        email: Email address pushed to or pulled from the application.
        first_name: Given name.
        last_name: Family name.
        employee_number: Employee number.
        user_type: User type.
        login: Login in the application; NameID fallback.
        dn: Active Directory distinguished name.
        cn: Active Directory common name.
        object_sid: Active Directory object SID; anchors the AD sync edges.
        sam_account_name: Active Directory sAMAccountName.
        immutable_id: Entra ID anchor of the assignment (Office 365 app).
        initial_status: Set by Okta on users pushed to an Org2Org app; its
            presence tells push from pull.
        department: Department; a plausible SAML claim source.
        city: City; a plausible SAML claim source.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")
    email: str | None = None
    first_name: str | None = Field(default=None, alias="firstName")
    last_name: str | None = Field(default=None, alias="lastName")
    employee_number: str | None = Field(default=None, alias="employeeNumber")
    user_type: str | None = Field(default=None, alias="userType")
    login: str | None = None
    dn: str | None = None
    cn: str | None = None
    object_sid: str | None = Field(default=None, alias="objectSid")
    sam_account_name: str | None = Field(default=None, alias="samAccountName")
    immutable_id: str | None = Field(default=None, alias="immutableId")
    initial_status: str | None = Field(default=None, alias="initialStatus")
    department: str | None = None
    city: str | None = None

    # Not collected.
    # country_code: str | None = Field(default=None, alias="countryCode")
    # division: str | None = None
    # organization: str | None = None
    # title: str | None = None
    # manager_id: str | None = Field(default=None, alias="managerId")
    # state: str | None = None
    # manager_dn: str | None = Field(default=None, alias="managerDn")


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
            kind=ek.SWA,
            start=nk.USER,
            end=nk.GITHUB_USER,
            traversable=False,
            description="User stores credentials for a GitHub account",
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
            kind=ek.SWA,
            start=nk.USER,
            end=nk.SNOWFLAKE_USER,
            traversable=False,
            description="User stores credentials for a Snowflake account",
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
        EdgeDef(
            kind=ek.SAML_HAS_CLAIM_VALUE,
            start=nk.USER,
            end=nk.SAML_CLAIM_MAPPING,
            traversable=False,
            description="Okta user has a value for an exceptional SAML claim",
        ),
    ],
)
class ApplicationUser(BaseAsset):
    """Assignment of an Okta user to an application.

    Only the assignment keys the edges and lookups consume are collected; see
    the module comment above.

    Attributes:
        id: Okta user ID of the assigned user.
        profile: Application-specific user profile without the skipped
            attributes.
        status: Assignment status.
        credentials: Application credentials, read for the target user name.
        external_id: ID of the user in the external application.
        app_id: Okta application ID.
        app_features: Enabled provisioning features of the application.
        app_name: Okta application name (OIN key).
        app_status: Application status.
        app_settings: Application settings, read by hybrid_user_target.
        app_sign_on_mode: Application sign-on mode.
        app_subject_name_id_template: SAML subject NameID template.
        app_subject_name_id_format: SAML subject NameID format.
        app_user_name_template: Application user name template.
        scope: "USER" for direct assignments, "GROUP" for group assignments.
        sync_state: Provisioning sync state of the assignment.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    profile: Profile
    status: str
    credentials: Credentials | None = None
    external_id: str | None = Field(default=None, alias="externalId")

    # Additional
    app_id: str
    app_features: list[str] = Field(default_factory=list)
    app_name: str
    app_status: str | None = None
    app_settings: dict[str, Any] | None = None
    app_sign_on_mode: str | None = None
    app_subject_name_id_template: str | None = None
    app_subject_name_id_format: str | None = None
    app_user_name_template: str | None = None

    # "USER" = directly assigned and "GROUP" = assigned via group membership.
    scope: str = Field(default="USER")
    sync_state: str | None = Field(default=None, alias="syncState")

    # Remaining attributes of the upstream assignment. Not collected; see the
    # module comment above.
    # created: datetime
    # last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    # password_changed: datetime | None = Field(default=None, alias="passwordChanged")

    @property
    def as_node(self) -> None:
        """Assignments are edges only; they emit no node."""
        return None

    @property
    def _read_password_updates_edge(self) -> Iterator[Edge]:
        """Application can read password updates of the user (push feature)."""
        if "PUSH_PASSWORD_UPDATES" in self.app_features:
            yield Edge(
                kind=ek.READ_PASSWORD_UPDATES,
                start=OktaOwnedEdgePath(value=self.app_id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _app_assignment_edge(self) -> Iterator[Edge]:
        """Direct user-to-application assignment."""
        # Note: Check if we want to filter default assignments (factual to the environment)
        # or filter out default assignments (to clean up the graph)
        if self.scope == "USER":
            yield Edge(
                kind=ek.APP_ASSIGNMENT,
                start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _target_user_name(self) -> str | None:
        """User name in the external application, if Okta stores one."""
        return self.credentials.username if self.credentials else None

    @property
    def _hybrid_sign_on_edges(self) -> Iterator[Edge]:
        """SSO or SWA edge to the matching account in another collector."""
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
            start=OktaOwnedEdgePath(value=self.id, match_by="id"),
            end=hybrid_target_edge_path(target),
            properties=HybridAuthEdgeProperties(
                traversable=edge_kind == ek.OUTBOUND_SSO,
                mode=self.app_sign_on_mode,
            ),
        )

    @property
    def _inbound_user_sync_enabled(self) -> bool:
        """Whether the application is a profile source for Okta users."""
        return "PROFILE_MASTERING" in self.app_features

    @property
    def _is_inbound_sync(self) -> bool:
        """Whether this assignment is pulled into Okta rather than pushed out."""
        if self.app_name == AppName.ACTIVE_DIRECTORY:
            return self.scope == "USER"

        if self.app_name == AppName.LDAP_INTERFACE:
            return True

        if self.scope == "GROUP":
            return False

        if self.app_name == AppName.OKTA_ORG2ORG:
            return (
                "initial_status" not in self.profile.model_fields_set
                and self._inbound_user_sync_enabled
            )

        return self._inbound_user_sync_enabled

    @property
    def _user_push_pull_edges(self) -> Iterator[Edge]:
        """Provisioning direction edge for synchronized assignments."""
        if self.sync_state != "SYNCHRONIZED":
            return

        if self._is_inbound_sync:
            yield Edge(
                kind=ek.USER_PULL,
                start=OktaOwnedEdgePath(value=self.app_id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )
        elif self.app_name not in IGNORED_OUTBOUND_SYNC_APPS:
            yield Edge(
                kind=ek.USER_PUSH,
                start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.app_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

    @property
    def _password_sync_edge(self) -> Iterator[Edge]:
        """User and password sync edges between an AD user and the Okta user."""
        if (
            self.sync_state == "SYNCHRONIZED"
            and self.app_name == AppName.ACTIVE_DIRECTORY
            and self.profile.object_sid
        ):
            if self._is_inbound_sync:
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=EdgePath(value=self.profile.object_sid, match_by="id"),
                    end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

                if "OUTBOUND_DEL_AUTH" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=EdgePath(value=self.profile.object_sid, match_by="id"),
                        end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )
            else:
                yield Edge(
                    kind=ek.USER_SYNC,
                    start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=self.profile.object_sid, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )
                if "PUSH_PASSWORD_UPDATES" in self.app_features:
                    yield Edge(
                        kind=ek.PASSWORD_SYNC,
                        start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                        end=EdgePath(value=self.profile.object_sid, match_by="id"),
                        properties=EdgeProperties(traversable=True),
                    )

    @property
    def _okta_org2org_edges(self) -> Iterator[Edge]:
        """User and password sync edges between users of two Okta orgs."""
        if self.app_name != AppName.OKTA_ORG2ORG or not self.external_id:
            return

        if self._is_inbound_sync:
            yield Edge(
                kind=ek.USER_SYNC,
                start=OktaOwnedEdgePath(value=self.external_id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

        else:
            yield Edge(
                kind=ek.USER_SYNC,
                start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                end=OktaOwnedEdgePath(value=self.external_id, match_by="id"),
                properties=EdgeProperties(traversable=False),
            )

            if "PUSH_PASSWORD_UPDATES" in self.app_features:
                yield Edge(
                    kind=ek.PASSWORD_SYNC,
                    start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                    end=OktaOwnedEdgePath(value=self.external_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def _saml_assertion_edges(self) -> Iterator[Edge]:
        """SAML eligibility and claim value edges for active SAML assignments."""
        if self.app_sign_on_mode != "SAML_2_0":
            return
        if self.app_status is not None and self.app_status != "ACTIVE":
            return
        if self.status not in {"ACTIVE", "PROVISIONED"}:
            return
        lookup: Any = getattr(self, "_lookup", None)
        combined_context_lookup: Any = getattr(lookup, "user_saml_context", None)
        combined_context_available = callable(combined_context_lookup)
        legacy_context_available = False
        if not combined_context_available:
            legacy_context_available = all(
                callable(getattr(lookup, method, None))
                for method in ("user_status", "user_profile")
            )
        lookup_available = callable(getattr(lookup, "saml_claim_mappings", None)) and (
            combined_context_available or legacy_context_available
        )
        if lookup_available:
            if combined_context_available:
                source_context = combined_context_lookup(self.id)
                source_user_status, source_profile = source_context or (None, None)
            else:
                source_user_status = lookup.user_status(self.id)
                source_profile = lookup.user_profile(self.id)
            claim_mappings = lookup.saml_claim_mappings(self.app_id)
        else:
            source_user_status = None
        if source_user_status in {
            "SUSPENDED",
            "DEPROVISIONED",
            "STAGED",
            "LOCKED_OUT",
        }:
            return
        evidence = (
            saml_application_assertion_evidence(
                self,
                claim_mappings=claim_mappings,
                source_profile=source_profile,
            )
            if lookup_available
            else saml_application_assertion_evidence(self)
        )
        source_properties = evidence["source_properties"]
        yield Edge(
            kind=ek.SAML_ELIGIBLE_FOR,
            start=OktaOwnedEdgePath(value=self.id, match_by="id"),
            end=OktaOwnedEdgePath(value=saml_provider_id(self.app_id), match_by="id"),
            properties=SamlMatchValuesEdgeProperties(
                traversable=False,
                match_values=evidence["match_values"],
                email_match_values=evidence["email_match_values"],
                upn_match_values=evidence["upn_match_values"],
                entra_object_id_match_values=evidence["entra_object_id_match_values"],
                scoped_exact_match_values=evidence["scoped_exact_match_values"],
                incomplete_match_value_fields=evidence["incomplete_match_value_fields"],
                source_property=(
                    source_properties[0]
                    if len(source_properties) == 1
                    else saml_match_source(
                        self.app_subject_name_id_template or self.app_user_name_template
                    )
                ),
                source_properties=source_properties,
                assignment_source=(
                    "direct_assignment" if self.scope == "USER" else "group_assignment"
                ),
            ),
        )
        for claim_value in evidence["claim_values"]:
            yield Edge(
                kind=ek.SAML_HAS_CLAIM_VALUE,
                start=OktaOwnedEdgePath(value=self.id, match_by="id"),
                end=OktaOwnedEdgePath(value=claim_value["mapping_id"], match_by="id"),
                properties=SamlResolutionValueEdgeProperties(
                    traversable=False,
                    match_values=claim_value["match_values"],
                    canonical_match_values=claim_value["canonical_match_values"],
                    unsafe_match_values=claim_value["unsafe_match_values"],
                    source_property=claim_value["source_property"],
                    incomplete=claim_value["incomplete"],
                ),
            )

    @property
    def edges(self) -> Iterator[Edge]:
        """All edges this assignment contributes to the graph."""
        yield from self._app_assignment_edge
        yield from self._read_password_updates_edge
        yield from self._user_push_pull_edges
        yield from self._password_sync_edge
        yield from self._okta_org2org_edges
        yield from self._hybrid_sign_on_edges
        yield from self._saml_assertion_edges
