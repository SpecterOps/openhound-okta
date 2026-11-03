"""Policy inventory and mapping collection."""

from dlt.extract.resource import DltResource

from openhound_okta.main import app
from openhound_okta.models import Policy, PolicyMapping, PolicyType
from openhound_okta.source_context import SourceContext


@app.resource(name="policy_types", parallelized=True, columns=PolicyType)
def policy_types():
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
    ]
    for policy_type in okta_policies:
        yield {"policy_type": policy_type}


@app.transformer(name="policies", columns=Policy, parallelized=True)
def policies(policy: dict, ctx: SourceContext):
    """DLT resource, fetches Okta policies via GET /policies.

    Yields:
        policy (Policy): Policy records.
    """
    policy_type = policy["policy_type"]
    for page in ctx.pool.paginate("/api/v1/policies", params={"type": policy_type}):
        for item in page:
            yield item


@app.transformer(name="policy_mappings", columns=PolicyMapping, parallelized=True)
def policy_mappings(policy: Policy, ctx: SourceContext):
    for page in ctx.pool.paginate(f"/api/v1/policies/{policy.id}/mappings"):
        for item in page:
            yield {
                "policy_id": policy.id,
                **item,
            }


def all_resources(ctx: SourceContext) -> tuple[DltResource, ...]:
    """Compose policy inventory and its mapping pipeline."""
    policies_resource = policy_types | policies(ctx)
    return (
        policies_resource,
        policies_resource | policy_mappings(ctx),
    )
