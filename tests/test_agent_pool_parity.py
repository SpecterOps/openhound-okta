from openhound_okta.kinds import edges as ek
from openhound_okta.models import Agent, AgentPool


class StubLookup:
    def __init__(self, *, has_backing_application: bool = True):
        self.has_backing_application = has_backing_application

    def org_id(self):
        return "org-1"

    def application_by_id(self, app_id):
        assert app_id == "app-or-pool-1"
        return app_id if self.has_backing_application else None


def make_agent_pool(*, pool_type: str = "AD", has_backing_application: bool = True):
    agent_pool = AgentPool.model_validate(
        {
            "id": "app-or-pool-1",
            "name": "corp.example.com",
            "type": pool_type,
            "operationalStatus": "OPERATIONAL",
            "agents": [],
        }
    )
    agent_pool._lookup = StubLookup(has_backing_application=has_backing_application)
    agent_pool._extras = {"tenant": "example.okta.com"}
    return agent_pool


def test_agent_pool_ids_are_namespaced_away_from_backing_app_ids():
    agent_pool = make_agent_pool()

    assert agent_pool.as_node.id == "APP-OR-POOL-1_POOL"
    assert agent_pool.as_node.properties.okta_domain == "example.okta.com"

    contains_edge = next(edge for edge in agent_pool.edges if edge.kind == ek.CONTAINS)
    assert contains_edge.end.value == "APP-OR-POOL-1_POOL"


def test_ad_agent_pool_for_edges_target_the_backing_application():
    agent_pool = make_agent_pool()

    edge = next(edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR)

    assert edge.start.value == "APP-OR-POOL-1_POOL"
    assert edge.end.value == "APP-OR-POOL-1"


def test_ldap_agent_pool_for_edges_target_the_backing_application():
    agent_pool = make_agent_pool(pool_type="LDAP")

    edge = next(edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR)

    assert edge.start.value == "APP-OR-POOL-1_POOL"
    assert edge.end.value == "APP-OR-POOL-1"


def test_ldap_agent_pools_without_backing_apps_do_not_emit_agent_pool_for_edges():
    agent_pool = make_agent_pool(pool_type="LDAP", has_backing_application=False)

    assert [edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR] == []


def test_non_directory_agent_pools_do_not_emit_agent_pool_for_edges():
    agent_pool = make_agent_pool(pool_type="RADIUS")

    assert [edge for edge in agent_pool.edges if edge.kind == ek.AGENT_POOL_FOR] == []


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


def test_ad_agents_match_host_computers_like_oktahound():
    agent = Agent.model_validate(
        {
            "id": "agent-1",
            "name": "WIN-region1A-dc",
            "version": "1.0.0",
            "poolId": "app-or-pool-1",
            "agent_pool_name": "region1A.dc",
            "agent_type": "AD",
        }
    )

    edge = next(agent._hosts_agent_edge)

    assert edge.kind == ek.HOSTS_AGENT
    assert edge.start.kind == "Computer"
    assert [
        (matcher.key, matcher.value) for matcher in edge.start.property_matchers
    ] == [
        ("samaccountname", "WIN-REGION1A-DC$"),
        ("domain", "REGION1A.DC"),
    ]
    assert edge.end.value == "AGENT-1"
    assert edge.properties.traversable is True


def test_non_ad_agents_do_not_emit_hosts_agent_edges():
    agent = Agent.model_validate(
        {
            "id": "agent-1",
            "name": "radius-agent",
            "version": "1.0.0",
            "poolId": "pool-1",
            "agent_pool_name": "RADIUS",
            "agent_type": "RADIUS",
        }
    )

    assert list(agent._hosts_agent_edge) == []


def test_agent_node_emits_oktahound_equivalent_properties():
    agent = Agent.model_validate(
        {
            "id": "agent-1",
            "name": "WIN-corp-dc",
            "type": "AD_AGENT",
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
    assert properties.type == "AD_AGENT"
    assert properties.operational_status == "OPERATIONAL"
    assert properties.update_status == "CURRENT"
    assert properties.last_connection.isoformat() == "2026-01-01T00:00:00+00:00"
