"""Okta organization collection resources and helpers."""

from dlt.extract import DltResource

from ..main import app
from ..models import Agent, AgentPool, Device, Organization, Realm
from ..source_context import SourceContext


@app.resource(name="organization", columns=Organization, parallelized=True)
def organization(ctx: SourceContext):
    """DLT resource, fetches Okta organization metadata via GET /api/v1/org.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        organization (Organization): Okta organization metadata record.
    """
    for page in ctx.pool.paginate("/api/v1/org"):
        yield page


@app.resource(name="devices", columns=Device, parallelized=True)
def devices(ctx: SourceContext):
    """DLT resource, fetches Okta devices via GET /devices.

    Yields:
        device (Device): Device records.
    """
    for page in ctx.pool.paginate("/api/v1/devices?expand=userSummary"):
        yield page


@app.resource(name="realms", columns=Realm, parallelized=True)
def realms(ctx: SourceContext):
    """DLT resource, fetches Okta realms via GET /api/v1/realms.

    Yields:
        realm (Realm): Realm records.
    """
    for page in ctx.pool.paginate("/api/v1/realms"):
        yield page


@app.resource(name="agent_pools", columns=AgentPool, parallelized=True)
def agent_pools(ctx: SourceContext):
    """DLT resource, fetches Okta agent pools via GET /api/v1/iam/agent-pools.

    Yields:
        agent_pool (AgentPool): Agent pool records.
    """
    for page in ctx.pool.paginate("/api/v1/agentPools"):
        for pool in page:
            yield pool


@app.transformer(name="agents", columns=Agent, parallelized=True)
def agents(agent_pool: AgentPool):
    """DLT transformer, yields the agents embedded in an agent pool.

    Args:
        agent_pool: Parent agent pool record.

    Yields:
        Agent rows tagged with agent_pool_name and agent_type.
    """
    for agent in agent_pool.agents or []:
        yield {
            **agent.model_dump(),
            "agent_pool_name": agent_pool.name,
            "agent_type": agent_pool.type,
        }


def all_resources(ctx: SourceContext) -> tuple[DltResource, ...]:
    """Compose organization inventory and the shared agent-pool pipeline."""
    agent_pools_resource = agent_pools(ctx)
    return (
        organization(ctx),
        devices(ctx),
        realms(ctx),
        agent_pools_resource,
        agent_pools_resource | agents(),
    )
