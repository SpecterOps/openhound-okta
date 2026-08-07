import duckdb
import pytest

from openhound_okta.kinds import edges as ek
from openhound_okta.kinds import nodes as nk
from openhound_okta.main import app
from openhound_okta.models import (
    ClientRoleAssignment,
    GroupRoleAssignment,
    PrivilegedUser,
    ResourceSetRoleAssignment,
    UserRoleAssignment,
)
from openhound_okta.source import (
    _is_direct_active_role_assignment,
    _role_assignment_scope,
    _resource_set_binding_assignee_id,
)
from openhound_okta.transforms import (
    insert_principals_with_admin_roles,
    non_admin_users,
    principals_with_admin_roles,
)


class StubLookup:
    def org_id(self):
        return "org-1"

    def role_assignment_exists(self, role_assignment_id, assignee_id):
        return True

    def role_assignment_resource_set_ids(self, role_assignment_id, assignee_id):
        return ()

    def group_by_id(self, group_id):
        return group_id in {"group-1", "group-2"}

    def application_by_id(self, app_id):
        return app_id in {"app-1", "app-2"}

    def application_ids_by_name(self, app_name):
        return [("app-2",)] if app_name == "catalog-app" else []

    def api_service_ids_by_name(self, app_name):
        return [("integration-1",)] if app_name == "catalog-app" else []

    def all_groups(self):
        return [("group-1",), ("group-2",)]

    def non_admin_groups(self):
        return [("group-1",), ("group-2",)]

    def all_users(self):
        return [("user-1",), ("user-2",)]

    def non_admin_users(self):
        return [("user-1",), ("user-2",)]

    def group_user_ids(self, group_ids):
        return ("user-1",) if "group-1" in group_ids else ()

    def all_applications(self):
        return [("app-1",), ("app-2",)]

    def non_admin_apps(self):
        return [("app-1",), ("app-2",)]

    def all_api_services(self):
        return [("integration-1",)]

    def application_secret_ids(self, app_id):
        return []

    def has_role_permission(self, role_id, permission):
        return False

    def resource_set_application_ids(self, resource_set_id):
        return ()

    def resource_set_non_admin_application_ids(self, resource_set_id):
        return ()

    def resource_set_non_admin_group_ids(self, resource_set_id):
        return ()

    def resource_set_non_admin_user_ids(self, resource_set_id):
        return ()


class StubLookupWithBinding(StubLookup):
    permissions = {"okta.users.credentials.resetPassword"}

    def role_assignment_resource_set_ids(self, role_assignment_id, assignee_id):
        return ("resource-set-1",)

    def has_role_permission(self, role_id, permission):
        return permission in self.permissions

    def resource_set_non_admin_user_ids(self, resource_set_id):
        return ("user-1",)


class StubLookupWithPermissions(StubLookupWithBinding):
    def __init__(self, permissions):
        self.permissions = set(permissions)


class StubLookupWithoutAssignment(StubLookup):
    def role_assignment_exists(self, role_assignment_id, assignee_id):
        return False


class StubLookupWithSecrets(StubLookup):
    def application_secret_ids(self, app_id):
        return [(f"secret-{app_id}",)]


def make_assignment(
    model_cls,
    *,
    from_resource: str,
    source_id: str,
    assignment_type: str,
    status: str = "ACTIVE",
    assignment_id: str = "role-assignment-1",
    role_type: str = "SUPER_ADMIN",
    **extra,
):
    payload = {
        "id": assignment_id,
        "from_resource": from_resource,
        "source_id": source_id,
        "assignmentType": assignment_type,
        "status": status,
        "created": None,
        "label": "Super Administrator",
        "type": role_type,
        **extra,
    }
    assignment = model_cls.model_validate(payload)
    assignment._lookup = StubLookup()
    assignment._extras = {"tenant": "example.okta.com"}
    return assignment


@pytest.mark.parametrize(
    ("model_cls", "from_resource", "assignment_type", "source_id"),
    [
        (UserRoleAssignment, "user", "USER", "user-1"),
        (GroupRoleAssignment, "group", "GROUP", "group-1"),
        (ClientRoleAssignment, "client", "CLIENT", "client-1"),
    ],
)
def test_role_assignment_nodes_use_oktahound_composite_ids(
    model_cls, from_resource, assignment_type, source_id
):
    assignment = make_assignment(
        model_cls,
        from_resource=from_resource,
        source_id=source_id,
        assignment_type=assignment_type,
    )

    assert assignment.node_id == f"role-assignment-1_{source_id}"
    assert assignment.as_node.id == assignment.node_id.upper()
    assert assignment.as_node.properties.okta_domain == "example.okta.com"

    has_role_assignment = next(
        edge for edge in assignment.edges if edge.kind == ek.HAS_ROLE_ASSIGNMENT
    )
    assert has_role_assignment.end.value == assignment.node_id.upper()

    contains = next(edge for edge in assignment.edges if edge.kind == ek.CONTAINS)
    assert contains.start.value == "ORG-1"
    assert contains.end.value == assignment.node_id.upper()


def test_same_role_assignment_id_is_unique_per_assignee():
    first = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
    )
    second = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-2",
        assignment_type="USER",
    )

    assert first.as_node.id == "ROLE-ASSIGNMENT-1_USER-1"
    assert second.as_node.id == "ROLE-ASSIGNMENT-1_USER-2"
    assert first.as_node.id != second.as_node.id


def test_built_in_role_assignment_has_role_edge_uses_domain_qualified_role_id():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="SUPER_ADMIN",
    )

    has_role = next(edge for edge in assignment.edges if edge.kind == ek.HAS_ROLE)

    assert has_role.end.value == "SUPER_ADMIN@EXAMPLE.OKTA.COM"


def test_privileged_users_are_returned_as_validated_models_for_transformers():
    assert PrivilegedUser.dlt_config == {"return_validated_models": True}


@pytest.mark.parametrize(
    ("model_cls", "from_resource", "direct_type", "indirect_type"),
    [
        (UserRoleAssignment, "user", "USER", "GROUP"),
        (GroupRoleAssignment, "group", "GROUP", "USER"),
        (ClientRoleAssignment, "client", "CLIENT", "GROUP"),
    ],
)
@pytest.mark.parametrize(
    ("status", "use_direct_type"),
    [
        ("INACTIVE", True),
        ("ACTIVE", False),
    ],
)
def test_inactive_and_indirect_assignments_do_not_emit_graph_entries(
    model_cls, from_resource, direct_type, indirect_type, status, use_direct_type
):
    assignment = make_assignment(
        model_cls,
        from_resource=from_resource,
        source_id=f"{from_resource}-1",
        assignment_type=direct_type if use_direct_type else indirect_type,
        status=status,
    )

    assert assignment.as_node is None
    assert list(assignment.edges) == []


@pytest.mark.parametrize(
    ("from_resource", "assignment_type", "status", "role_type", "expected"),
    [
        ("user", "USER", "ACTIVE", "SUPER_ADMIN", True),
        ("user", "USER", "ACTIVE", "CUSTOM", True),
        ("user", "GROUP", "ACTIVE", "SUPER_ADMIN", False),
        ("group", "GROUP", "ACTIVE", "SUPER_ADMIN", True),
        ("group", "USER", "ACTIVE", "SUPER_ADMIN", False),
        ("client", "CLIENT", "ACTIVE", "SUPER_ADMIN", True),
        ("client", "CLIENT", "INACTIVE", "SUPER_ADMIN", False),
        ("user", "USER", "ACTIVE", "ACCESS_REQUEST_ADMIN", False),
    ],
)
def test_collection_filter_keeps_only_direct_active_assignments(
    from_resource, assignment_type, status, role_type, expected
):
    assert (
        _is_direct_active_role_assignment(
            {
                "assignmentType": assignment_type,
                "status": status,
                "type": role_type,
            },
            from_resource,
        )
        is expected
    )


def test_admin_principal_transform_uses_privileged_user_inventory():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.privileged_users (id VARCHAR)")
    con.execute(
        "CREATE TABLE okta.user_role_assignments "
        "(source_id VARCHAR, status VARCHAR, assignment_type VARCHAR)"
    )
    con.execute(
        "CREATE TABLE okta.group_role_assignments "
        "(source_id VARCHAR, status VARCHAR, assignment_type VARCHAR)"
    )
    con.execute(
        "CREATE TABLE okta.client_role_assignments "
        "(source_id VARCHAR, status VARCHAR, assignment_type VARCHAR)"
    )
    con.execute(
        "INSERT INTO okta.privileged_users VALUES "
        "('direct-user'), "
        "('inherited-user')"
    )
    con.execute(
        "INSERT INTO okta.user_role_assignments VALUES "
        "('direct-user', 'ACTIVE', 'USER'), "
        "('inherited-user', 'ACTIVE', 'GROUP'), "
        "('inactive-user', 'INACTIVE', 'USER')"
    )
    con.execute(
        "INSERT INTO okta.group_role_assignments VALUES "
        "('direct-group', 'ACTIVE', 'GROUP'), "
        "('wrong-group', 'ACTIVE', 'USER')"
    )
    con.execute(
        "INSERT INTO okta.client_role_assignments VALUES "
        "('direct-client', 'ACTIVE', 'CLIENT'), "
        "('inactive-client', 'INACTIVE', 'CLIENT')"
    )

    principals_with_admin_roles(con)
    insert_principals_with_admin_roles(con)

    assert con.execute(
        "SELECT id, principal_type FROM okta.principals_with_admin_roles "
        "ORDER BY principal_type, id"
    ).fetchall() == [
        ("direct-client", "client"),
        ("direct-group", "group"),
        ("direct-user", "user"),
        ("inherited-user", "user"),
    ]


def test_non_admin_users_excludes_inherited_admins_from_privileged_inventory():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.users (id VARCHAR)")
    con.execute("CREATE TABLE okta.privileged_users (id VARCHAR)")
    con.execute(
        "CREATE TABLE okta.user_role_assignments "
        "(source_id VARCHAR, status VARCHAR, assignment_type VARCHAR)"
    )
    con.execute("INSERT INTO okta.users VALUES ('direct-user'), ('inherited-user'), ('plain-user')")
    con.execute("INSERT INTO okta.privileged_users VALUES ('direct-user'), ('inherited-user')")
    con.execute(
        "INSERT INTO okta.user_role_assignments VALUES "
        "('direct-user', 'ACTIVE', 'USER')"
    )

    principals_with_admin_roles(con)
    insert_principals_with_admin_roles(con)
    non_admin_users(con)

    assert con.execute("SELECT id FROM okta.non_admin_users ORDER BY id").fetchall() == [
        ("plain-user",)
    ]


def test_org_wide_standard_role_assignment_is_scoped_to_org():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="API_ACCESS_MANAGEMENT_ADMIN",
    )

    edges = list(assignment._scoped_to_org_edge)

    assert len(edges) == 1
    assert edges[0].start.value == assignment.node_id.upper()
    assert edges[0].end.value == "ORG-1"


@pytest.mark.parametrize(
    ("role_type", "scope_field"),
    [
        ("APP_ADMIN", "scope_apps"),
        ("USER_ADMIN", "scope_groups"),
        ("GROUP_MEMBERSHIP_ADMIN", "scope_groups"),
        ("HELP_DESK_ADMIN", "scope_groups"),
    ],
)
def test_targetable_standard_role_assignment_with_empty_scope_is_scoped_to_org(
    role_type, scope_field
):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type=role_type,
        **{scope_field: []},
    )

    assert next(assignment._scoped_to_org_edge).end.value == "ORG-1"


@pytest.mark.parametrize(
    "role_type",
    [
        "APP_ADMIN",
        "USER_ADMIN",
        "GROUP_MEMBERSHIP_ADMIN",
        "HELP_DESK_ADMIN",
    ],
)
def test_targetable_standard_role_assignment_without_collected_scope_does_not_invent_org_scope(
    role_type,
):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type=role_type,
    )

    assert list(assignment._scoped_to_org_edge) == []


def test_group_targeted_standard_role_assignment_is_not_scoped_to_org():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="HELP_DESK_ADMIN",
        scope_groups=[{"id": "group-1"}],
    )

    assert list(assignment._scoped_to_org_edge) == []
    assert next(assignment._scoped_to_group_edges).end.value == "GROUP-1"
    assert next(assignment._helpdesk_admin_edges).end.value == "USER-1"


@pytest.mark.parametrize(
    "role_type",
    [
        "WORKFLOWS_ADMIN",
    ],
)
def test_resource_set_scoped_built_in_roles_do_not_fall_back_to_org(role_type):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type=role_type,
    )

    assert list(assignment._scoped_to_org_edge) == []


@pytest.mark.parametrize(
    "role_type",
    [
        "API_ADMIN",
        "ACCESS_CERTIFICATIONS_ADMIN",
        "ACCESS_REQUEST_ADMIN",
        "ACCESS_REQUESTS_ADMIN",
    ],
)
def test_unsupported_built_in_role_assignments_do_not_emit_graph_content(role_type):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type=role_type,
    )

    assert assignment.as_node is None
    assert list(assignment.edges) == []


def test_group_and_client_assignments_emit_app_scope_edges():
    for model_cls, from_resource, assignment_type in (
        (GroupRoleAssignment, "group", "GROUP"),
        (ClientRoleAssignment, "client", "CLIENT"),
    ):
        assignment = make_assignment(
            model_cls,
            from_resource=from_resource,
            source_id=f"{from_resource}-1",
            assignment_type=assignment_type,
            role_type="APP_ADMIN",
            scope_apps=[
                {
                    "id": "app-1",
                    "name": "example",
                    "displayName": "Example",
                    "status": "ACTIVE",
                    "category": "example",
                }
            ],
        )

        assert next(assignment._scoped_to_app_edges).end.value == "APP-1"
        assert list(assignment._scoped_to_org_edge) == []


def test_catalog_app_target_resolves_applications_and_integrations():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="APP_ADMIN",
        scope_apps=[
            {
                "name": "catalog-app",
                "displayName": "Catalog App",
                "status": "ACTIVE",
                "category": "example",
            }
        ],
    )

    assert assignment.scoped_app_ids == ("app-2", "integration-1")


@pytest.mark.parametrize(
    "scope_apps",
    [
        [
            {
                "id": "missing-app",
                "name": "missing",
                "displayName": "Missing",
                "status": "ACTIVE",
                "category": "example",
            }
        ],
        [
            {
                "id": "app-1",
                "name": "example",
                "displayName": "Example",
                "status": "INACTIVE",
                "category": "example",
            }
        ],
    ],
)
def test_configured_app_scope_without_resolved_targets_does_not_fall_back_to_org(
    scope_apps,
):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="APP_ADMIN",
        scope_apps=scope_apps,
    )
    assignment._lookup = StubLookupWithSecrets()

    assert assignment.scoped_app_ids == ()
    assert assignment._permission_app_ids == ()
    assert list(assignment._scoped_to_org_edge) == []
    assert list(assignment._app_admin_edges) == []
    assert list(assignment.read_client_secret_edges) == []


def test_custom_role_assignment_does_not_use_resource_set_link_for_scope():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="CUSTOM",
        role="custom-role-1",
        _links={
            "resource-set": {
                "href": "https://example.okta.com/api/v1/iam/resource-sets/resource-set-1"
            }
        },
    )

    assert list(assignment._scoped_to_org_edge) == []
    assert [edge for edge in assignment.edges if edge.kind == ek.SCOPED_TO] == []


def test_custom_role_permission_edges_use_collected_binding_scope():
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="CUSTOM",
        role="custom-role-1",
        _links={
            "resource-set": {
                "href": "https://example.okta.com/api/v1/iam/resource-sets/resource-set-1"
            }
        },
    )
    assignment._lookup = StubLookupWithBinding()

    assert assignment.resource_set_ids == ("resource-set-1",)
    assert next(assignment._reset_password_edges).end.value == "USER-1"


@pytest.mark.parametrize(
    ("permission", "reset_password", "reset_factors"),
    [
        ("okta.users.credentials.resetPassword", True, False),
        ("okta.users.credentials.manage", True, True),
        ("okta.users.credentials.manageTemporaryAccessCode", True, False),
        ("okta.users.credentials.expirePassword", True, False),
        ("okta.users.credentials.resetFactors", False, True),
        ("okta.users.manage", True, True),
    ],
)
def test_custom_role_credential_permissions_emit_expected_edges(
    permission, reset_password, reset_factors
):
    assignment = make_assignment(
        UserRoleAssignment,
        from_resource="user",
        source_id="user-1",
        assignment_type="USER",
        role_type="CUSTOM",
        role="custom-role-1",
    )
    assignment._lookup = StubLookupWithPermissions({permission})

    assert bool(list(assignment._reset_password_edges)) is reset_password
    assert bool(list(assignment._reset_factors_edges)) is reset_factors


def test_resource_set_role_assignment_emits_scoped_to_edge_for_collected_assignment():
    binding = ResourceSetRoleAssignment.model_validate(
        {
            "id": "role-assignment-1",
            "resource_set_id": "resource-set-1",
            "role_id": "custom-role-1",
            "assignee_id": "user-1",
        }
    )
    binding._lookup = StubLookup()

    edge = next(binding.edges)

    assert edge.kind == ek.SCOPED_TO
    assert edge.start.value == "ROLE-ASSIGNMENT-1_USER-1"
    assert edge.end.value == "RESOURCE-SET-1"


def test_resource_set_role_assignment_skips_missing_role_assignment():
    binding = ResourceSetRoleAssignment.model_validate(
        {
            "id": "role-assignment-1",
            "resource_set_id": "resource-set-1",
            "role_id": "custom-role-1",
            "assignee_id": "user-1",
        }
    )
    binding._lookup = StubLookupWithoutAssignment()

    assert list(binding.edges) == []


def test_resource_set_binding_assignee_id_uses_self_href():
    assert (
        _resource_set_binding_assignee_id(
            {
                "_links": {
                    "self": {
                        "href": "https://example.okta.com/api/v1/users/user-1",
                    }
                }
            }
        )
        == "user-1"
    )


@pytest.mark.parametrize(
    ("from_resource", "source_id", "role_type", "expected_path", "scope_field"),
    [
        (
            "user",
            "user-1",
            "APP_ADMIN",
            "/api/v1/users/user-1/roles/role-assignment-1/targets/catalog/apps",
            "scope_apps",
        ),
        (
            "group",
            "group-1",
            "HELP_DESK_ADMIN",
            "/api/v1/groups/group-1/roles/role-assignment-1/targets/groups",
            "scope_groups",
        ),
        (
            "client",
            "client-1",
            "APP_ADMIN",
            "/oauth2/v1/clients/client-1/roles/role-assignment-1/targets/catalog/apps",
            "scope_apps",
        ),
    ],
)
def test_role_assignment_scope_uses_dedicated_target_endpoints(
    from_resource, source_id, role_type, expected_path, scope_field
):
    class StubPool:
        def __init__(self):
            self.paths = []

        def paginate(self, path):
            self.paths.append(path)
            return [[{"id": "target-1"}]]

    class StubContext:
        def __init__(self):
            self.pool = StubPool()

    ctx = StubContext()
    result = _role_assignment_scope(
        {"id": "role-assignment-1", "type": role_type},
        from_resource,
        source_id,
        ctx,
    )

    assert ctx.pool.paths == [expected_path]
    assert result == {scope_field: [{"id": "target-1"}]}


def test_role_assignment_scope_does_not_publish_partial_targets_after_failure():
    class StubPool:
        def paginate(self, path):
            yield [{"id": "target-1"}]
            raise RuntimeError("second page failed")

    class StubContext:
        def __init__(self):
            self.pool = StubPool()

    result = _role_assignment_scope(
        {"id": "role-assignment-1", "type": "APP_ADMIN"},
        "user",
        "user-1",
        StubContext(),
    )

    assert result == {}


def test_scoped_to_edge_definitions_start_from_role_assignment_nodes():
    scoped_to_edges = [edge for edge in app.edges if edge.kind == ek.SCOPED_TO]

    assert scoped_to_edges
    assert {edge.start for edge in scoped_to_edges} == {nk.ROLE_ASSIGNMENT}
