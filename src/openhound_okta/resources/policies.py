"""Okta policies collection resources and helpers."""

import logging

import requests
from dlt.extract import DltResource

from ..main import app
from ..models import Policy, PolicyMapping, PolicyType
from ..source_context import SourceContext

logger = logging.getLogger(__name__)


@app.resource(name="policy_types", parallelized=True, columns=PolicyType)
def policy_types():
    """DLT resource, yields the policy types whose policies are collected.

    Yields:
        {"policy_type": type} for each collected type.
    """
    okta_policies = [
        "OKTA_SIGN_ON",
        "PASSWORD",
        "MFA_ENROLL",
        "IDP_DISCOVERY",
        "ACCESS_POLICY",
        "DEVICE_SIGNAL_COLLECTION",
        "PROFILE_ENROLLMENT",
        "POST_AUTH_SESSION",
        "ENTITY_RISK",
        "SESSION_VIOLATION_DETECTION",
        "CLIENT_UPDATE",
        # Early Access; orgs without the feature answer 400 for this type.
        "IDENTITY_CLAIM_SOURCING",
    ]
    for policy_type in okta_policies:
        yield {"policy_type": policy_type}


@app.transformer(name="policies", columns=Policy, parallelized=True)
def policies(policy: dict, ctx: SourceContext):
    """DLT resource, fetches Okta policies via GET /policies.

    A policy type the org does not support (for example an Early Access type
    that is not enabled) answers 400; that type is logged as a warning and
    skipped so the remaining types are still collected. Other HTTP errors
    propagate.

    Yields:
        policy (Policy): Policy records.
    """
    policy_type = policy["policy_type"]
    try:
        for page in ctx.pool.paginate("/api/v1/policies", params={"type": policy_type}):
            for item in page:
                yield item
    except requests.HTTPError as e:
        status_code = getattr(e.response, "status_code", None)
        if status_code != 400:
            raise
        try:
            # e.g. E0000002 "The request was not valid: Invalid policy type
            # specified. Missing Required Feature Flag SUPPORT_FOR_REAUTH_WITH_EXTERNAL_IDP"
            body = e.response.json()
            detail = f"{body.get('errorCode')} {body.get('errorSummary')}"
        except (ValueError, AttributeError):
            detail = str(e)
        logger.warning(
            "Skipping policy type %s, which is not available in this org: %s",
            policy_type,
            detail,
            extra={"resource": "policies", "phase": "collect"},
        )


@app.transformer(name="policy_mappings", columns=PolicyMapping, parallelized=True)
def policy_mappings(policy: Policy, ctx: SourceContext):
    """DLT transformer, fetches a policy's resource mappings via GET /policies/{id}/mappings.

    Args:
        policy: Parent policy record.
        ctx: Source context providing the client pool.

    Yields:
        Mapping rows tagged with policy_id.
    """
    for page in ctx.pool.paginate(f"/api/v1/policies/{policy.id}/mappings"):
        for item in page:
            yield {
                "policy_id": policy.id,
                **item,
            }


def all_resources(ctx: SourceContext) -> tuple[DltResource, ...]:
    """Compose policy and mapping pipelines from one policy-type stream."""
    policies_resource = policy_types | policies(ctx)
    return (
        policies_resource,
        policies_resource | policy_mappings(ctx),
    )
