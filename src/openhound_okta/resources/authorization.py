"""Role, permission, resource-set and authorization-server collection."""

import logging
from collections.abc import Mapping
from urllib.parse import urlparse

from dlt.extract.resource import DltResource

from openhound_okta.main import app
from openhound_okta.models import (
    ApiToken,
    AuthServer,
    BuiltInRole,
    BuiltInRolePermission,
    ClientApplication,
    ClientRoleAssignment,
    CustomRole,
    CustomRolePermission,
    Group,
    GroupRoleAssignment,
    PrivilegedUser,
    Resource,
    ResourceSet,
    ResourceSetRoleAssignment,
    UserRoleAssignment,
)
from openhound_okta.models.built_in_role import (
    BUILT_IN_ROLES,
    SUPPORTED_ROLE_ASSIGNMENT_TYPES,
    UNSUPPORTED_BUILT_IN_ROLES,
)
from openhound_okta.models.built_in_role_permission import BUILT_IN_PERMISSIONS
from openhound_okta.models.role_assignment import (
    DIRECT_ASSIGNMENT_TYPES,
    GROUP_TARGETED_ROLE_TYPES,
)
from openhound_okta.source_context import SourceContext
from openhound_okta.utils.http import OktaRetryExhaustedError

logger = logging.getLogger(__name__)


def _is_direct_active_role_assignment(
    item: Mapping[str, object], from_resource: str
) -> bool:
    return (
        item.get("status") == "ACTIVE"
        and item.get("assignmentType") == DIRECT_ASSIGNMENT_TYPES.get(from_resource)
        and item.get("type") in SUPPORTED_ROLE_ASSIGNMENT_TYPES
    )


def _last_href_path_segment(href: str | None) -> str | None:
    if not href:
        return None

    path = urlparse(href).path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else None


def _resource_set_binding_assignee_id(member: Mapping[str, object]) -> str | None:
    links = member.get("_links")
    if not isinstance(links, Mapping):
        return None

    link = links.get("self")
    if isinstance(link, Mapping):
        return _last_href_path_segment(link.get("href"))

    return None


def _role_assignment_base_path(from_resource: str, source_id: str) -> str:
    if from_resource == "client":
        return f"/oauth2/v1/clients/{source_id}/roles"
    return f"/api/v1/{from_resource}s/{source_id}/roles"


def _role_assignment_scope(
    item: Mapping[str, object],
    from_resource: str,
    source_id: str,
    ctx: "SourceContext",
) -> dict[str, list[object]]:
    role_type = item.get("type")
    assignment_id = item.get("id")
    if not isinstance(assignment_id, str):
        return {}

    if role_type == "APP_ADMIN":
        target_path = (
            f"{_role_assignment_base_path(from_resource, source_id)}"
            f"/{assignment_id}/targets/catalog/apps"
        )
        scope_field = "scope_apps"
    elif role_type in GROUP_TARGETED_ROLE_TYPES:
        target_path = (
            f"{_role_assignment_base_path(from_resource, source_id)}"
            f"/{assignment_id}/targets/groups"
        )
        scope_field = "scope_groups"
    else:
        return {}

    try:
        targets = [target for page in ctx.pool.paginate(target_path) for target in page]
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            "Error fetching scope for role assignment %s on %s %s: %s",
            assignment_id,
            from_resource,
            source_id,
            e,
            extra={"resource": "role_assignment_scope", "phase": "defer"},
        )
        return {}

    return {scope_field: targets}


@app.transformer(
    name="client_role_assignments", columns=ClientRoleAssignment, parallelized=True
)
def client_role_assignments(client: ClientApplication, ctx: SourceContext):
    if client.application_type == "service":
        for page in ctx.pool.paginate(f"/oauth2/v1/clients/{client.client_id}/roles"):
            for item in page:
                if _is_direct_active_role_assignment(item, "client"):
                    yield {
                        "from_resource": "client",
                        "source_id": client.client_id,
                        **item,
                        **_role_assignment_scope(item, "client", client.client_id, ctx),
                    }


@app.resource(name="built_in_roles", columns=BuiltInRole, parallelized=True)
def built_in_roles():
    """DLT resource, yields a static list of built-in Okta roles.

    Yields:
        role (Role): Okta built-in role record.
    """

    for role in BUILT_IN_ROLES:
        yield {"type": role}


@app.transformer(
    name="user_role_assignments", columns=UserRoleAssignment, parallelized=True
)
def user_role_assignments(user: PrivilegedUser, ctx: SourceContext):
    """Fetch direct active role assignments and their scopes for a privileged user."""
    try:
        for roles in ctx.pool.paginate(f"/api/v1/users/{user.id}/roles"):
            for role in roles:
                if _is_direct_active_role_assignment(role, "user"):
                    yield {
                        "from_resource": "user",
                        "source_id": user.id,
                        **role,
                        **_role_assignment_scope(role, "user", user.id, ctx),
                    }
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            f"Error in resource 'user_role_assignments' processing assignee_details: {e}",
            extra={"resource": "user_role_assignments", "phase": "defer"},
        )
        return


@app.transformer(
    name="group_role_assignments", columns=GroupRoleAssignment, parallelized=True
)
def group_role_assignments(group: Group, ctx: SourceContext):
    if group.embedded.stats.has_admin_privilege:
        for page in ctx.pool.paginate(f"/api/v1/groups/{group.id}/roles"):
            for role in page:
                if _is_direct_active_role_assignment(role, "group"):
                    yield {
                        "from_resource": "group",
                        "source_id": group.id,
                        **role,
                        **_role_assignment_scope(role, "group", group.id, ctx),
                    }


@app.transformer(
    name="built_in_role_permissions", columns=BuiltInRolePermission, parallelized=True
)
def built_in_role_permissions(role: BuiltInRole):
    """DLT resource, yields permissions for Okta built-in roles.

    Yields:
        permission (BuiltInRolePermission): Built-in role permission records.
    """

    permissions = BUILT_IN_PERMISSIONS.get(role.type, [])
    for permission in permissions:
        yield {"role_label": role.type, "role_id": role.type, "label": permission}


@app.resource(name="custom_roles", columns=CustomRole, parallelized=True)
def custom_roles(ctx: SourceContext):
    """DLT resource, fetches custom Okta roles via GET /roles.

    Yields:
        role (CustomRole): Okta role record.
    """
    for page in ctx.pool.paginate("/api/v1/iam/roles"):
        for item in page:
            # For whatever reason the WORKFLOWS_ADMIN also shows up in the custom roles endpoint
            if item["id"] in UNSUPPORTED_BUILT_IN_ROLES:
                continue
            if item["id"] not in BUILT_IN_PERMISSIONS:
                yield item


@app.transformer(
    name="custom_role_permissions", columns=CustomRolePermission, parallelized=True
)
def custom_role_permissions(role: CustomRole, ctx: SourceContext):
    """DLT resource, fetches permissions for a custom Okta role via GET /api/v1/iam/roles/{roleId}/permissions.

    Yields:
        permission (CustomRolePermission): Custom role permission records.
    """

    for page in ctx.pool.paginate(f"/api/v1/iam/roles/{role.id}/permissions"):
        for item in page:
            item["role_id"] = role.id
            item["role_label"] = role.label
            yield item


@app.resource(name="authorization_servers", columns=AuthServer, parallelized=True)
def authorization_servers(ctx: SourceContext):
    """DLT resource, fetches Okta authorization servers via GET /api/v1/authorizationServers.

    Yields:
        authorization (AuthServer): AuthServer server records.
    """
    for page in ctx.pool.paginate("/api/v1/authorizationServers"):
        yield page


@app.resource(name="resource_sets", columns=ResourceSet, parallelized=True)
def resource_sets(ctx: SourceContext):
    """DLT resource, fetches Okta resource sets via GET /api/v1/iam/resource-sets.

    Yields:
        resource_set (ResourceSet): Resource set records.
    """
    for page in ctx.pool.paginate("/api/v1/iam/resource-sets"):
        for item in page:
            yield item


@app.transformer(name="resources", columns=Resource, parallelized=True)
def resources(resource_set: ResourceSet, ctx: SourceContext):
    for page in ctx.pool.paginate(
        f"api/v1/iam/resource-sets/{resource_set.id}/resources"
    ):
        for item in page:
            yield {"resource_set_id": resource_set.id, **item}


@app.transformer(
    name="resource_set_role_assignments",
    columns=ResourceSetRoleAssignment,
    parallelized=True,
)
def resource_set_role_assignments(resource_set: ResourceSet, ctx: SourceContext):
    for page in ctx.pool.paginate(
        f"/api/v1/iam/resource-sets/{resource_set.id}/bindings",
        data_selector="roles",
    ):
        for role in page:
            role_id = role.get("id")
            if not role_id:
                continue

            for member_page in ctx.pool.paginate(
                f"/api/v1/iam/resource-sets/{resource_set.id}/bindings/{role_id}/members",
                data_selector="members",
            ):
                for member in member_page:
                    assignee_id = _resource_set_binding_assignee_id(member)
                    if not assignee_id:
                        logger.warning(
                            "Skipping resource set role assignment member %s without an assignee link",
                            member.get("id"),
                        )
                        continue

                    yield {
                        "resource_set_id": resource_set.id,
                        "role_id": role_id,
                        "assignee_id": assignee_id,
                        **member,
                    }


@app.resource(name="api_tokens", columns=ApiToken, parallelized=True)
def api_tokens(ctx: SourceContext):
    """DLT resource, fetches Okta API tokens via GET /api/v1/api-tokens.

    Yields:
        api_token (ApiToken): API token records.
    """
    for page in ctx.pool.paginate("/api/v1/api-tokens"):
        yield page


def all_resources(ctx: SourceContext) -> tuple[DltResource, ...]:
    """Compose role, permission and resource-set pipelines."""
    custom_roles_resource = custom_roles(ctx)
    built_in_roles_resource = built_in_roles()
    resource_sets_resource = resource_sets(ctx)
    return (
        authorization_servers(ctx),
        resource_sets_resource,
        resource_sets_resource | resources(ctx),
        resource_sets_resource | resource_set_role_assignments(ctx),
        custom_roles_resource,
        custom_roles_resource | custom_role_permissions(ctx),
        api_tokens(ctx),
        built_in_roles_resource,
        built_in_roles_resource | built_in_role_permissions,
    )
