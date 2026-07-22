from openhound_okta.kinds import edges as ek
from openhound_okta.models import Agent, AgentPool


class StubLookup:
    def org_id(self):
        return "org-1"


def make_agent_pool(*, pool_type: str = "AD"):
    agent_pool = AgentPool.model_validate(
        {
            "id": "app-or-pool-1",
            "name": "corp.example.com",
            "type": pool_type,
            "operationalStatus": "OPERATIONAL",
            "agents": [],
        }
    )
    agent_pool._lookup = StubLookup()
    agent_pool._extras = {"tenant": "example.okta.com"}
    return agent_pool


def test_agent_pool_ids_are_namespaced_away_from_backing_app_ids():
    agent_pool = make_agent_pool()

    assert agent_pool.as_node.id == "app-or-pool-1_pool"

    contains_edge = next(
        edge for edge in agent_pool.edges if edge.kind == ek.CONTAINS
    )
    assert contains_edge.end.value == "app-or-pool-1_pool"


def test_ad_agent_pool_for_edges_target_the_backing_application():
    agent_pool = make_agent_pool()

    edge = next(edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR)

    assert edge.start.value == "app-or-pool-1_pool"
    assert edge.end.value == "app-or-pool-1"


def test_non_ad_agent_pools_do_not_emit_agent_pool_for_edges():
    agent_pool = make_agent_pool(pool_type="RADIUS")

    assert [
        edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR
    ] == []


def test_agent_member_of_edges_target_namespaced_pool_ids():
    agent = Agent.model_validate(
        {
            "id": "agent-1",
            "name": "WIN-corp-dc",
            "version": "1.0.0",
            "poolId": "app-or-pool-1",
            "agent_type": "AD",
        }
    )

    edge = next(agent._agent_member_of_edge)

    assert edge.kind == ek.AGENT_MEMBER_OF
    assert edge.start.value == "agent-1"
    assert edge.end.value == "app-or-pool-1_pool"
