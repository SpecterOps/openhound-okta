import duckdb

from openhound_okta.kinds import edges as ek
from openhound_okta.lookup import OktaLookup
from openhound_okta.models import (
    Resource,
    ResourceSet,
    ResourceSetRoleAssignment,
    UserRoleAssignment,
)


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

    resource = make_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:groups:group-1:users",
        resource_url,
    )
    edges = list(resource.edges)
    assert [(edge.kind, edge.end.value) for edge in edges] == [
        (ek.RESOURCE_SET_CONTAINS_MEMBERS_OF, "GROUP-1"),
        (ek.RESOURCE_SET_CONTAINS_INDIRECT, "USER-1"),
    ]
    assert all(edge.properties.traversable is False for edge in edges)


def test_group_member_resource_set_orns_resolve_group_members_without_urls():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1'), ('user-2')")
    lookup.client.execute("INSERT INTO okta.groups VALUES ('group-1')")
    lookup.client.execute(
        "INSERT INTO okta.group_memberships VALUES ('user-1', 'group-1')"
    )
    orn = "orn:okta:directory:org-1:groups:group-1:users"

    assert lookup.resolve_resource_orn(orn) == ("user-1",)

    resource = Resource.model_validate(
        {"resource_set_id": "resource-set-1", "orn": orn}
    )
    resource._lookup = lookup
    resource._extras = {"tenant": "example.okta.com"}

    assert [(edge.kind, edge.end.value) for edge in resource.edges] == [
        (ek.RESOURCE_SET_CONTAINS_MEMBERS_OF, "GROUP-1"),
        (ek.RESOURCE_SET_CONTAINS_INDIRECT, "USER-1"),
    ]


def test_group_member_resources_for_unknown_groups_emit_no_edges():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1')")
    resource = make_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:groups:group-missing:users",
        "https://example.okta.com/api/v1/groups/group-missing/users",
    )

    assert list(resource.edges) == []


def test_direct_and_indirect_edges_cover_all_resource_set_members():
    lookup = make_lookup()
    lookup.client.execute(
        "INSERT INTO okta.users VALUES ('user-1'), ('user-2'), ('user-3')"
    )
    lookup.client.execute("INSERT INTO okta.groups VALUES ('group-1'), ('group-2')")
    lookup.client.execute(
        "INSERT INTO okta.group_memberships VALUES "
        "('user-2', 'group-1'), ('user-3', 'group-1'), ('user-1', 'group-2')"
    )
    resources = [
        (
            "orn:okta:directory:org-1:users:user-1",
            "https://example.okta.com/api/v1/users/user-1",
        ),
        (
            "orn:okta:directory:org-1:groups:group-1:users",
            "https://example.okta.com/api/v1/groups/group-1/users",
        ),
        (
            "orn:okta:directory:org-1:groups:group-2",
            "https://example.okta.com/api/v1/groups/group-2",
        ),
    ]
    for orn, resource_url in resources:
        insert_resource(lookup, "resource-set-1", orn, resource_url)

    edges = [
        edge
        for orn, resource_url in resources
        for edge in make_resource(lookup, "resource-set-1", orn, resource_url).edges
    ]
    edges_by_kind: dict[str, set[str]] = {}
    for edge in edges:
        edges_by_kind.setdefault(edge.kind, set()).add(edge.end.value.lower())

    assert edges_by_kind == {
        ek.RESOURCE_SET_CONTAINS: {"user-1", "group-2"},
        ek.RESOURCE_SET_CONTAINS_MEMBERS_OF: {"group-1"},
        ek.RESOURCE_SET_CONTAINS_INDIRECT: {"user-2", "user-3"},
    }
    assert all(edge.properties.traversable is False for edge in edges)

    # Direct + indirect membership edges match the members used for role scoping.
    member_ids = (
        edges_by_kind[ek.RESOURCE_SET_CONTAINS]
        | edges_by_kind[ek.RESOURCE_SET_CONTAINS_INDIRECT]
    )
    assert member_ids == set(lookup.resource_set_member_ids("resource-set-1"))
    assert lookup.resource_set_user_ids("resource-set-1") == (
        "user-1",
        "user-2",
        "user-3",
    )
    assert lookup.resource_set_group_ids("resource-set-1") == ("group-2",)


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
    resource_url = 'https://example.okta.com/api/v1/apps?filter=name+eq+"githubcloud"'
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
        "APP-1",
        "INTEGRATION-1",
    }


def test_custom_role_permissions_scoped_to_resource_sets_cover_indirect_members():
    lookup = make_lookup()
    con = lookup.client
    con.execute("CREATE TABLE okta.non_admin_users (id VARCHAR)")
    con.execute("CREATE TABLE okta.non_admin_groups (id VARCHAR)")
    con.execute(
        "CREATE TABLE okta.custom_role_permissions (role_id VARCHAR, label VARCHAR)"
    )
    con.execute(
        "CREATE TABLE okta.resource_set_role_assignments "
        "(id VARCHAR, assignee_id VARCHAR, resource_set_id VARCHAR)"
    )
    # admin-1 holds the role; direct-user is a direct member of the resource
    # set; indirect-user is a member only through the Retail Staff group.
    con.execute(
        "INSERT INTO okta.users VALUES ('admin-1'), ('direct-user'), ('indirect-user')"
    )
    con.execute(
        "INSERT INTO okta.non_admin_users VALUES ('direct-user'), ('indirect-user')"
    )
    con.execute("INSERT INTO okta.groups VALUES ('retail-staff'), ('store-managers')")
    con.execute(
        "INSERT INTO okta.non_admin_groups VALUES ('retail-staff'), ('store-managers')"
    )
    con.execute(
        "INSERT INTO okta.group_memberships VALUES ('indirect-user', 'retail-staff')"
    )
    con.execute(
        "INSERT INTO okta.custom_role_permissions VALUES "
        "('custom-role-1', 'okta.users.credentials.manage'), "
        "('custom-role-1', 'okta.groups.members.manage')"
    )
    con.execute(
        "INSERT INTO okta.user_role_assignments VALUES ('role-assignment-1', 'admin-1')"
    )
    con.execute(
        "INSERT INTO okta.resource_set_role_assignments VALUES "
        "('role-assignment-1', 'admin-1', 'resource-set-1')"
    )
    insert_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:users:direct-user",
        "https://example.okta.com/api/v1/users/direct-user",
    )
    insert_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:groups:retail-staff:users",
        "https://example.okta.com/api/v1/groups/retail-staff/users",
    )
    insert_resource(
        lookup,
        "resource-set-1",
        "orn:okta:directory:org-1:groups:store-managers",
        "https://example.okta.com/api/v1/groups/store-managers",
    )

    assignment = UserRoleAssignment.model_validate(
        {
            "id": "role-assignment-1",
            "from_resource": "user",
            "source_id": "admin-1",
            "assignmentType": "USER",
            "status": "ACTIVE",
            "created": None,
            "label": "Authentication Admins",
            "type": "CUSTOM",
            "role": "custom-role-1",
        }
    )
    assignment._lookup = lookup
    assignment._extras = {"tenant": "example.okta.com"}

    targets_by_kind: dict[str, set[str]] = {}
    for edge in assignment.edges:
        targets_by_kind.setdefault(edge.kind, set()).add(edge.end.value.lower())

    # Users reachable through Okta_ResourceSetContains and
    # Okta_ResourceSetContainsIndirect are both in scope of the permissions.
    assert targets_by_kind[ek.RESET_PASSWORD] == {"direct-user", "indirect-user"}
    assert targets_by_kind[ek.RESET_FACTORS] == {"direct-user", "indirect-user"}
    # Only the directly contained group is manageable; a group whose members
    # are in the resource set is not itself in scope.
    assert set(edge.end.value.lower() for edge in assignment.add_member_edges) == {
        "store-managers"
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


def test_invalid_self_links_fall_back_to_orn_resolution():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1')")

    for self_link in (None, "not-a-link", [], {"href": None}):
        resource = Resource.model_validate(
            {
                "resource_set_id": "resource-set-1",
                "orn": "orn:okta:directory:org-1:users:user-1",
                "_links": {"self": self_link},
            }
        )
        resource._lookup = lookup
        resource._extras = {"tenant": "example.okta.com"}

        assert resource.resource_url is None
        assert [edge.end.value for edge in resource.edges] == ["USER-1"]


def test_policy_member_resource_set_urls_resolve_policy_ids():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.policies VALUES ('policy-1', 'PASSWORD')")
    resource_url = "https://example.okta.com/api/v1/policies/policy-1"

    assert lookup.resolve_resource_url(resource_url) == ("policy-1",)


def test_workflows_resource_set_ids_are_tenant_qualified_across_graph_edges():
    lookup = make_lookup()
    lookup.client.execute("INSERT INTO okta.users VALUES ('user-1')")
    lookup.client.execute(
        "INSERT INTO okta.user_role_assignments VALUES ('role-assignment-1', 'user-1')"
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

    assert resource_set.as_node.id == "WORKFLOWS_IAM_POLICY@EXAMPLE.OKTA.COM"
    assert next(resource_set.edges).end.value == "WORKFLOWS_IAM_POLICY@EXAMPLE.OKTA.COM"

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
    assert next(binding.edges).end.value == "WORKFLOWS_IAM_POLICY@EXAMPLE.OKTA.COM"

    resource = make_resource(
        lookup,
        "WORKFLOWS_IAM_POLICY",
        "orn:okta:directory:org-1:users:user-1",
        "https://example.okta.com/api/v1/users/user-1",
    )
    edge = next(resource.edges)
    assert edge.kind == ek.RESOURCE_SET_CONTAINS
    assert edge.start.value == "WORKFLOWS_IAM_POLICY@EXAMPLE.OKTA.COM"
    assert edge.properties.traversable is False


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
    assert properties.name == "HELP DESK USERS"
    assert properties.displayname == "Help Desk Users"
    assert properties.okta_domain == "example.okta.com"
    assert properties.description == "Scoped help desk users"
    assert not hasattr(properties, "label")
