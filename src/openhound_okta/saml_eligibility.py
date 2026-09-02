"""Contract-local helpers for additive Okta SAML group-eligibility evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from uuid import UUID, uuid5


SAML_V0_4_CONTRACT_VERSION = "opengraph-saml-v0.4.0"
SAML_GROUP_ELIGIBILITY_PROFILE = "openhound_okta_group_membership_v1"
SAML_GROUP_ELIGIBILITY_MODE_EXPANDED = "expanded"
SAML_GROUP_ELIGIBILITY_MODE_SHADOW = "shadow"
SAML_GROUP_ELIGIBILITY_MODES = frozenset(
    {
        SAML_GROUP_ELIGIBILITY_MODE_EXPANDED,
        SAML_GROUP_ELIGIBILITY_MODE_SHADOW,
    }
)
SAML_ELIGIBILITY_ROOT_NAMESPACE = UUID("18bc451f-b58c-58e2-87e3-2e93b0c77581")


def parse_saml_group_eligibility_mode(value: object) -> str:
    """Return one supported producer mode, rejecting accidental cutover values."""

    if not isinstance(value, str) or value not in SAML_GROUP_ELIGIBILITY_MODES:
        raise ValueError(
            "saml_group_eligibility_mode must be expanded or shadow"
        )
    return value


def configured_saml_group_eligibility_mode(
    config_get: Callable[[str], object | None],
) -> str:
    """Read canonical and legacy DLT config paths with an expanded default."""

    value = config_get("sources.okta.saml_group_eligibility_mode")
    if value is None:
        value = config_get("sources.source.okta.saml_group_eligibility_mode")
    return parse_saml_group_eligibility_mode(
        SAML_GROUP_ELIGIBILITY_MODE_EXPANDED if value is None else value
    )


def saml_principal_reachability_state(status: str | None) -> str:
    """Map native Okta lifecycle state to the registered v0.4 vocabulary."""

    if status in {"ACTIVE", "PROVISIONED", "PASSWORD_EXPIRED", "RECOVERY"}:
        return "enabled"
    if status in {"LOCKED_OUT", "SUSPENDED", "DEPROVISIONED", "STAGED"}:
        return "blocked"
    return "unknown"


def canonical_group_assignment_policy_identity(group_ids: tuple[str, ...]) -> str:
    """Build the exact selector identity from already-canonical graph IDs."""

    operands = tuple(sorted(set(group_ids)))
    if not operands:
        raise ValueError("SAML group eligibility requires at least one group assignment")
    selector = "single" if len(operands) == 1 else "any_of"
    return f"{selector}:" + ",".join(
        f"positive_set:{group_id}" for group_id in operands
    )


@dataclass(frozen=True)
class SamlGroupEligibilityIdentity:
    """Contract-derived v0.4 identity keys for one native Okta group operand."""

    canonical_policy_identity: str
    canonical_branch_identity: str
    policy_key: str
    branch_key: str
    partition_key: str
    evidence_key: str
    selector_operator: str
    branch_positive_operand_count: int


def derive_saml_group_eligibility_identity(
    *,
    source_id: str,
    authority_id: str,
    federation_provider_id: str,
    assigned_group_ids: tuple[str, ...],
    group_id: str,
) -> SamlGroupEligibilityIdentity:
    """Derive the immutable v0.4 chain for a normalized graph operand."""

    canonical_policy_identity = canonical_group_assignment_policy_identity(
        assigned_group_ids
    )
    canonical_branch_identity = canonical_policy_identity
    source_namespace = uuid5(SAML_ELIGIBILITY_ROOT_NAMESPACE, source_id)
    authority_namespace = uuid5(source_namespace, authority_id)
    provider_namespace = uuid5(authority_namespace, federation_provider_id)
    policy_key = uuid5(provider_namespace, canonical_policy_identity)
    basis_namespace = uuid5(policy_key, "group_assignment")
    partition_key = uuid5(basis_namespace, "partition")
    branch_key = uuid5(partition_key, canonical_branch_identity)
    evidence_key = uuid5(branch_key, f"positive_set:{group_id}")
    return SamlGroupEligibilityIdentity(
        canonical_policy_identity=canonical_policy_identity,
        canonical_branch_identity=canonical_branch_identity,
        policy_key=str(policy_key),
        branch_key=str(branch_key),
        partition_key=str(partition_key),
        evidence_key=str(evidence_key),
        selector_operator=canonical_policy_identity.split(":", 1)[0],
        branch_positive_operand_count=len(tuple(sorted(set(assigned_group_ids)))),
    )
