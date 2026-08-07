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

    assert agent_pool.as_node.id == "APP-OR-POOL-1_POOL"
    assert agent_pool.as_node.properties.okta_domain == "example.okta.com"

    contains_edge = next(
        edge for edge in agent_pool.edges if edge.kind == ek.CONTAINS
    )
    assert contains_edge.end.value == "APP-OR-POOL-1_POOL"


def test_ad_agent_pool_for_edges_target_the_backing_application():
    agent_pool = make_agent_pool()

    edge = next(edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR)

    assert edge.start.value == "APP-OR-POOL-1_POOL"
    assert edge.end.value == "APP-OR-POOL-1"


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
    assert edge.start.value == "AGENT-1"
    assert edge.end.value == "APP-OR-POOL-1_POOL"


def test_agent_node_emits_oktahound_equivalent_properties():
    agent = Agent.model_validate(
        {
            "id": "agent-1",
            "name": "WIN-corp-dc",
            "version": "1.0.0",
            "operationalStatus": "OPERATIONAL",
            "poolId": "app-or-pool-1",
            "lastConnection": "2026-01-01T00:00:00Z",
            "updateStatus": "CURRENT",
            "agent_pool_name": "corp.example.com",
            "agent_type": "AD",
        }
    )
    agent._lookup = StubLookup()
    agent._extras = {"tenant": "example.okta.com"}

    properties = agent.as_node.properties

    assert properties.okta_domain == "example.okta.com"
    assert properties.pool_id == "app-or-pool-1"
    assert properties.pool_name == "corp.example.com"
    assert properties.operational_status == "OPERATIONAL"
    assert properties.update_status == "CURRENT"
    assert properties.last_connection.isoformat() == "2026-01-01T00:00:00+00:00"
