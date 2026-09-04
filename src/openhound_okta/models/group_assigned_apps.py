from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Any

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaOwnedEdgePath
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.saml import (
    SamlPrincipalSetEligibilityEdgeProperties,
    saml_provider_id,
)
from openhound_okta.saml_eligibility import (
    SAML_GROUP_ELIGIBILITY_MODE_SHADOW,
    SAML_GROUP_ELIGIBILITY_PROFILE,
    SAML_V0_4_CONTRACT_VERSION,
    derive_saml_group_eligibility_identity,
)


class Settings(BaseModel):
    app: dict | None = None
    notifications: dict | None = None
    manual_provisioning: bool | None = Field(default=None, alias="manualProvisioning")
    implicit_assignment: bool | None = Field(default=None, alias="implicitAssignment")
    em_opt_in_status: str | None = Field(default=None, alias="emOptInStatus")
    notes: dict | None = None
    oauth_client: dict | None = Field(default=None, alias="oauthClient")


class Credentials(BaseModel):
    user_name_template: dict | None = Field(default=None, alias="userNameTemplate")
    signing: dict | None = None
    oauth_client: dict | None = Field(default=None, alias="oauthClient")


@dataclass
class AppAssignmentEdgeProperties(EdgeProperties):
    """Non-sensitive provenance for a native Okta application assignment.

    Attributes:
        assignment_last_updated: Timestamp of the native Okta assignment update.
        assignment_priority: Native Okta group-assignment priority.
        assignment_profile_fields: Sorted assignment-profile field names. Values
            are intentionally excluded because they may contain sensitive data.
    """

    assignment_last_updated: datetime | None = None
    assignment_priority: int | None = None
    assignment_profile_fields: list[str] = dc_field(default_factory=list)


@app.asset(
    description="Okta assigned application asset",
    edges=[
        EdgeDef(
            kind=ek.APP_ASSIGNMENT,
            start=nk.GROUP,
            end=nk.APPLICATION,
            description="Group is assigned to an application",
        ),
        EdgeDef(
            kind=ek.SAML_ELIGIBLE_FOR,
            start=nk.GROUP,
            end=nk.SAML_FEDERATION_PROVIDER,
            description="Group is eligible for an Okta SAML federation provider",
        ),
    ],
)
class GroupAssignedApp(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    label: str
    status: str
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")

    group_id: str
    # Retained in raw/preprocessed evidence for later SAML compactability checks.
    app_sign_on_mode: str | None = None
    assignment_last_updated: datetime | None = None
    assignment_priority: int | None = None
    assignment_profile: dict[str, Any] | None = None

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        lookup = getattr(self, "_lookup", None)
        group_by_id = getattr(lookup, "group_by_id", None)
        if not self.group_id:
            raise ValueError("application-group assignment is missing its group ID")
        if not callable(group_by_id):
            raise RuntimeError(
                "application-group assignment conversion requires group lookup"
            )
        if not group_by_id(self.group_id):
            raise ValueError(
                "application-group assignment references uncollected Okta group "
                f"{self.group_id} for application {self.id}"
            )

        yield Edge(
            kind=ek.APP_ASSIGNMENT,
            start=OktaOwnedEdgePath(value=self.group_id, match_by="id"),
            end=OktaOwnedEdgePath(value=self.id, match_by="id"),
            properties=AppAssignmentEdgeProperties(
                traversable=False,
                assignment_last_updated=self.assignment_last_updated,
                assignment_priority=self.assignment_priority,
                assignment_profile_fields=(
                    sorted(self.assignment_profile) if self.assignment_profile else []
                ),
            ),
        )

        if (
            getattr(self, "_extras", {}).get("saml_group_eligibility_mode")
            != SAML_GROUP_ELIGIBILITY_MODE_SHADOW
        ):
            return
        if self.app_sign_on_mode != "SAML_2_0" or self.status != "ACTIVE":
            return

        group_ids_lookup = getattr(lookup, "saml_group_assignment_group_ids", None)
        org_id_lookup = getattr(lookup, "org_id", None)
        if not callable(group_ids_lookup) or not callable(org_id_lookup):
            raise RuntimeError(
                "SAML group eligibility conversion requires assignment and organization lookups"
            )
        assigned_group_ids = tuple(
            str(group_id).upper() for group_id in group_ids_lookup(self.id)
        )
        group_id = self.group_id.upper()
        if group_id not in assigned_group_ids:
            raise ValueError(
                "application-group assignment is absent from its authoritative "
                f"assignment set for application {self.id}"
            )
        org_id = org_id_lookup()
        if not org_id:
            raise RuntimeError(
                "SAML group eligibility conversion requires an Okta organization ID"
            )
        tenant_domain = getattr(self, "_extras", {}).get("tenant")
        if not isinstance(tenant_domain, str) or not tenant_domain:
            raise RuntimeError(
                "SAML group eligibility conversion requires an Okta tenant domain"
            )
        identity = derive_saml_group_eligibility_identity(
            source_id=f"source://openhound-okta/{str(org_id).upper()}",
            authority_id=f"https://{tenant_domain.lower()}",
            federation_provider_id=saml_provider_id(self.id).upper(),
            assigned_group_ids=assigned_group_ids,
            group_id=group_id,
        )
        preflight_lookup = getattr(lookup, "saml_eligibility_preflight", None)
        preflight = preflight_lookup(self.id) if callable(preflight_lookup) else None
        policy_evaluability = "static_incomplete"
        if preflight is not None:
            coverage_values = {
                "membership_coverage": preflight.membership_coverage,
                "principal_reachability_coverage": (
                    preflight.principal_reachability_coverage
                ),
                "principal_exclusion_coverage": (
                    preflight.principal_exclusion_coverage
                ),
                "policy_evaluation_coverage": preflight.policy_evaluation_coverage,
                "claim_evidence_coverage": preflight.claim_evidence_coverage,
            }
            policy_evaluability = preflight.policy_evaluability
        else:
            coverage = "unproven"
            coverage_values = {
                "membership_coverage": coverage,
                "principal_reachability_coverage": coverage,
                "principal_exclusion_coverage": coverage,
                "policy_evaluation_coverage": coverage,
                "claim_evidence_coverage": coverage,
            }
        yield Edge(
            kind=ek.SAML_ELIGIBLE_FOR,
            start=OktaOwnedEdgePath(value=self.group_id, match_by="id"),
            end=OktaOwnedEdgePath(
                value=saml_provider_id(self.id), match_by="id"
            ),
            properties=SamlPrincipalSetEligibilityEdgeProperties(
                traversable=False,
                schema_contract_version=SAML_V0_4_CONTRACT_VERSION,
                eligibility_subject_type="principal_set",
                eligibility_expansion_profile=SAML_GROUP_ELIGIBILITY_PROFILE,
                eligibility_identity_mode="contract_uuidv5",
                eligibility_source_id=f"source://openhound-okta/{str(org_id).upper()}",
                eligibility_authority_id=f"https://{tenant_domain.lower()}",
                canonical_policy_identity=identity.canonical_policy_identity,
                canonical_branch_identity=identity.canonical_branch_identity,
                eligibility_policy_key=identity.policy_key,
                eligibility_branch_key=identity.branch_key,
                eligibility_partition_key=identity.partition_key,
                eligibility_evidence_key=identity.evidence_key,
                eligibility_basis="group_assignment",
                selector_operator=identity.selector_operator,
                operand_role="positive_set",
                policy_evaluability=policy_evaluability,
                policy_branch_count=1,
                branch_positive_operand_count=(
                    identity.branch_positive_operand_count
                ),
                membership_coverage=coverage_values["membership_coverage"],
                principal_reachability_coverage=coverage_values[
                    "principal_reachability_coverage"
                ],
                principal_exclusion_coverage=coverage_values[
                    "principal_exclusion_coverage"
                ],
                policy_evaluation_coverage=coverage_values[
                    "policy_evaluation_coverage"
                ],
                claim_evidence_coverage=coverage_values["claim_evidence_coverage"],
            ),
        )
