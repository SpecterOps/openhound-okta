import duckdb

from openhound_okta.kinds import edges as ek
from openhound_okta.lookup import OktaLookup
from openhound_okta.models import Resource, ResourceSet, ResourceSetRoleAssignment


def make_lookup() -> OktaLookup:
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.organization (id VARCHAR)")
    con.execute("CREATE TABLE okta.users (id VARCHAR)")
    con.execute("CREATE TABLE okta.groups (id VARCHAR)")
    con.execute("CREATE TABLE okta.group_memberships (id VARCHAR, group_id VARCHAR)")
    con.execute("CREATE TABLE okta.applications (id VARCHAR, name VARCHAR)")
    con.execute("CREATE TABLE okta.api_services (id VARCHAR, type VARCHAR)")
    con.execute("CREATE TABLE okta.authorization_servers (id VARCHAR)")
    con.execute("CREATE TABLE okta.devices (id VARCHAR)")
    con.execute("CREATE TABLE okta.identity_providers (id VARCHAR)")
    con.execute("CREATE TABLE okta.policies (id VARCHAR, type VARCHAR)")
    con.execute(
        "CREATE TABLE okta.resources "
        "(resource_set_id VARCHAR, orn VARCHAR, _links JSON)"
    )
    con.execute(
        "CREATE TABLE okta.user_role_assignments (id VARCHAR, source_id VARCHAR)"
    )
    con.execute("INSERT INTO okta.organization VALUES ('org-1')")
    return OktaLookup(con)


def insert_resource(
    lookup: OktaLookup, resource_set_id: str, orn: str, resource_url: str
) -> None:
    lookup.client.execute(
        "INSERT INTO okta.resources VALUES (?, ?, ?)",
        [resource_set_id, orn, {"self": {"href": resource_url}}],
    )


def make_resource(
    lookup: OktaLookup, resource_set_id: str, orn: str, resource_url: str
) -> Resource:
    resource = Resource.model_validate(
        {
            "resource_set_id": resource_set_id,
            "orn": orn,
            "_links": {"self": {"href": resource_url}},
        }
    )
    resource._lookup = lookup
    resource._extras = {"tenant": "example.okta.com"}
    return resource


def test_group_member_resource_set_urls_resolve_users_not_groups():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1'), ('user-2')")
    lookup.client.execute("INSERT INTO okta.groups VALUES ('group-1')")
    lookup.client.execute(
        "INSERT INTO okta.group_memberships VALUES ('user-1', 'group-1')"
    )
    resource_url = "https://example.okta.com/api/v1/groups/group-1/users"
    insert_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:groups:group-1:users",
        resource_url,
    )

    assert lookup.resolve_resource_url(resource_url) == ("user-1",)
    assert lookup.resource_set_user_ids("resource-set-1") == ("user-1",)
    assert lookup.resource_set_group_ids("resource-set-1") == ()


def test_filtered_app_resource_set_urls_include_integrations_in_graph_edges():
    lookup = make_lookup()
    lookup.client.execute(
        "INSERT INTO okta.applications VALUES "
        "('app-1', 'githubcloud'), "
        "('app-2', 'office365')"
    )
    lookup.client.execute(
        "INSERT INTO okta.api_services VALUES "
        "('integration-1', 'githubcloud'), "
        "('integration-2', 'other')"
    )
    resource_url = (
        'https://example.okta.com/api/v1/apps?filter=name+eq+"githubcloud"'
    )
    insert_resource(
        lookup,
        "resource-set-1",
        "orn:okta:idp:org-1:apps:githubcloud",
        resource_url,
    )

    assert lookup.resolve_resource_url(resource_url) == ("app-1", "integration-1")
    assert lookup.resource_set_application_ids("resource-set-1") == ("app-1",)

    resource = make_resource(
        lookup,
        "resource-set-1",
        "orn:okta:idp:org-1:apps:githubcloud",
        resource_url,
    )
    assert {edge.end.value for edge in resource.edges} == {
        "app-1",
        "integration-1",
    }


def test_present_but_unresolved_resource_urls_do_not_fall_back_to_orns():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1')")
    resource = make_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:users",
        "https://example.okta.com/api/v1/unsupported",
    )

    assert list(resource.edges) == []


def test_workflows_resource_set_ids_are_tenant_qualified_across_graph_edges():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1')")
    lookup.client.execute(
        "INSERT INTO okta.user_role_assignments VALUES "
        "('role-assignment-1', 'user-1')"
    )

    resource_set = ResourceSet.model_validate(
        {
            "id": "WORKFLOWS_IAM_POLICY",
            "label": "Workflows",
            "created": "2026-01-01T00:00:00Z",
        }
    )
    resource_set._lookup = lookup
    resource_set._extras = {"tenant": "example.okta.com"}

    assert resource_set.as_node.id == "WORKFLOWS_IAM_POLICY@example.okta.com"
    assert next(resource_set.edges).end.value == "WORKFLOWS_IAM_POLICY@example.okta.com"

    binding = ResourceSetRoleAssignment.model_validate(
        {
            "id": "role-assignment-1",
            "resource_set_id": "WORKFLOWS_IAM_POLICY",
            "role_id": "custom-role-1",
            "assignee_id": "user-1",
        }
    )
    binding._lookup = lookup
    binding._extras = {"tenant": "example.okta.com"}
    assert next(binding.edges).end.value == "WORKFLOWS_IAM_POLICY@example.okta.com"

    resource = make_resource(
        lookup,
        "WORKFLOWS_IAM_POLICY",
        "orn:okta:directory:org-1:users:user-1",
        "https://example.okta.com/api/v1/users/user-1",
    )
    edge = next(resource.edges)
    assert edge.kind == ek.RESOURCE_SET_CONTAINS
    assert edge.start.value == "WORKFLOWS_IAM_POLICY@example.okta.com"


def test_resource_set_node_emits_oktahound_equivalent_properties():
    lookup = make_lookup()
    resource_set = ResourceSet.model_validate(
        {
            "id": "resource-set-1",
            "label": "Help Desk Users",
            "description": "Scoped help desk users",
            "created": "2026-01-01T00:00:00Z",
            "lastUpdated": "2026-01-02T00:00:00Z",
        }
    )
    resource_set._lookup = lookup
    resource_set._extras = {"tenant": "example.okta.com"}

    properties = resource_set.as_node.properties

    assert properties.id == "resource-set-1"
    assert properties.name == "Help Desk Users"
    assert properties.displayname == "Help Desk Users"
    assert properties.okta_domain == "example.okta.com"
    assert properties.description == "Scoped help desk users"
    assert not hasattr(properties, "label")
