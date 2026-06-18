import fnmatch
import logging
import xml.etree.ElementTree as ET
from base64 import b64decode
from dataclasses import dataclass
from typing import Any, Union

import dlt
from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration
from dlt.sources.helpers.rest_client.auth import APIKeyAuth
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator

from .main import app
from .models import (
    Agent,
    AgentPool,
    ApiService,
    ApiToken,
    Application,
    ApplicationGroupMapping,
    ApplicationJWKS,
    ApplicationSecrets,
    ApplicationUser,
    AuthServer,
    BuiltInRole,
    BuiltInRolePermission,
    ClientApplication,
    ClientRoleAssignment,
    CustomRole,
    CustomRolePermission,
    Device,
    Group,
    GroupAssignedApp,
    GroupMembership,
    GroupRoleAssignment,
    IdentityProvider,
    IDPUser,
    Organization,
    Policy,
    PolicyMapping,
    PolicyType,
    Realm,
    Resource,
    ResourceSet,
    SamlAssertionConsumerService,
    SamlFederationProvider,
    SamlIssuer,
    User,
    UserRoleAssignment,
)
from .models.saml import (
    saml_acs_rows,
    saml_federation_provider_row,
    saml_issuer_row,
)
from .models.built_in_role import BUILT_IN_ROLES
from .models.built_in_role_permission import BUILT_IN_PERMISSIONS
from .utils.auth import OktaAuth

logger = logging.getLogger(__name__)

OKTA_DEFAULT_SCOPE = [
    "okta.users.read",
    "okta.apps.read",
    "okta.groups.read",
    "okta.roles.read",
    "okta.agentPools.read",
    "okta.apiTokens.read",
    "okta.authorizationServers.read",
    "okta.devices.read",
    "okta.policies.read",
    "okta.orgs.read",
    "okta.idps.read",
    "okta.features.read",
    "okta.clients.read",
    "okta.appGrants.read",
    "okta.oauthIntegrations.read",
    "okta.authenticators.read",
    # Optional scopes which require a dedicated license
    "okta.realms.read",
    "okta.realmAssignments.read",
]

API_RATE_LIMIT_ENDPOINTS = [
    "/api/v1/users*",
    "/api/v1/groups*",
    "/api/v1/apps*",
    "/api/v1/iam*",
    "/api/v1/devices*",
    "/oauth2/v1/clients*",
    "*",
]


@configspec
class OktaCredentials(CredentialsConfiguration):
    base_url: str = None

    def auth(self):
        pass


@configspec
class OktaAppCredentials(OktaCredentials):
    private_key_path: str = None
    client_id: str = None

    def auth(self) -> str:
        return "app"

    @property
    def header(self) -> str:
        okta_auth = OktaAuth(private_key_path=self.private_key_path)
        private_key = okta_auth.private_key
        jwt = okta_auth.jwt(
            private_key=private_key,
            client_id=self.client_id,
            audience=f"{self.base_url}/oauth2/v1/token",
            exp_delta=60,
        )
        bearer_token = okta_auth.token(self.base_url, jwt, " ".join(OKTA_DEFAULT_SCOPE))
        return f"Bearer {bearer_token}"


@configspec
class OktaEncodedAppCredentials(OktaCredentials):
    private_key_b64: str = None
    client_id: str = None

    def auth(self) -> str:
        return "app"

    @property
    def header(self) -> str:
        decoded_credentials = b64decode(self.private_key_b64).decode("utf-8")
        okta_auth = OktaAuth(private_key_string=decoded_credentials)
        private_key = okta_auth.private_key
        jwt = okta_auth.jwt(
            private_key=private_key,
            client_id=self.client_id,
            audience=f"{self.base_url}/oauth2/v1/token",
            exp_delta=60,
        )
        bearer_token = okta_auth.token(self.base_url, jwt, " ".join(OKTA_DEFAULT_SCOPE))
        return f"Bearer {bearer_token}"


@configspec
class OktaTokenCredentials(OktaCredentials):
    token: str = None

    def auth(self) -> str:
        return "token"

    @property
    def header(self) -> str:
        return f"SSWS {self.token}"


class ClientPool:
    def __init__(self, base_url: str, auth, paginator):
        self._clients: dict[str, RESTClient] = {
            pattern: RESTClient(
                base_url=base_url,
                headers={"accept": "application/json"},
                auth=auth,
                paginator=paginator,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        self._saml_metadata_client = RESTClient(
            base_url=base_url,
            headers={"accept": "application/xml"},
            auth=auth,
            paginator=paginator,
        )

    def get_client(self, path: str) -> RESTClient:
        for pattern in self._clients:
            if fnmatch.fnmatch(path, pattern):
                return self._clients[pattern]
        return self._clients["*"]

    def paginate(self, path: str, **kwargs):
        return self.get_client(path).paginate(path, **kwargs)

    def get(self, path: str, **kwargs):
        return self.get_client(path).get(path, **kwargs)

    def get_saml_metadata(self, path: str):
        return self._saml_metadata_client.get(path)


@dataclass
class SourceContext:
    """Context for Okta API operations."""

    pool: ClientPool


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


@app.resource(name="users", columns=User, parallelized=True)
def users(ctx: SourceContext):
    """DLT resource, fetches Okta users via GET /users.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        user (User): Okta user record.
    """
    for page in ctx.pool.paginate("/api/v1/users"):
        for user in page:
            yield user


# TODO: Disabled until we find a more efficient way to process factors
# @app.transformer(name="factors", parallelized=True)
# def factors(user: User, ctx: SourceContext):
#     for page in ctx.pool.paginate(f"/api/v1/users/{user.id}/factors"):
#         yield page


@app.resource(
    name="groups",
    columns=Group,
    parallelized=True,
    write_disposition="replace",
)
def groups(ctx: SourceContext):
    """DLT resource, fetches Okta groups via GET /groups.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        group (Group): Okta group record.
    """
    # Example of saving state
    # last_run = dlt.current.resource_state().setdefault("last_run", None)
    for page in ctx.pool.paginate("/api/v1/groups?expand=stats"):
        for item in page:
            yield item

    # dlt.current.resource_state()["last_run"] = str(datetime.now().isoformat())


@app.transformer(
    name="group_memberships",
    columns=GroupMembership,
    parallelized=True,
    write_disposition="replace",
)
def group_memberships(group: Group, ctx: SourceContext):
    if group.embedded.stats.users_count > 0:
        for page in ctx.pool.paginate(f"/api/v1/groups/{group.id}/users"):
            for item in page:
                yield {"group_id": group.id, **item}


@app.transformer(
    name="group_assigned_apps", columns=GroupAssignedApp, parallelized=True
)
def group_assigned_apps(group: Group, ctx: SourceContext):
    """DLT resource, fetches apps assigned to groups via /api/v1/groups/{group_id}/apps

    Args:
        group (Group): Okta group record.
        ctx (SourceContext): SourceContext containing the REST client for API calls.

    Yields:
        _type_: _description_
    """
    if group.embedded.stats.apps_count > 0:
        for page in ctx.pool.paginate(f"/api/v1/groups/{group.id}/apps"):
            for item in page:
                yield {"group_id": group.id, **item}


@app.resource(name="applications", columns=Application, parallelized=True)
def applications(ctx: SourceContext):
    """DLT resource, fetches Okta applications via GET /api/v1/apps.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        application (Application): Okta application record.
    """
    for page in ctx.pool.paginate("/api/v1/apps"):
        for item in page:
            if item.get("signOnMode") == "SAML_2_0":
                item = {**item, **_saml_metadata_fields(ctx, item)}
            yield item


def _saml_metadata_fields(ctx: SourceContext, application: dict[str, Any]) -> dict[str, str]:
    metadata_link = (application.get("_links") or {}).get("metadata") or {}
    if not metadata_link.get("href"):
        return {}

    app_id = application.get("id")
    if not app_id:
        return {}

    try:
        response = ctx.pool.get_saml_metadata(f"/api/v1/apps/{app_id}/sso/saml/metadata")
        metadata = response.text
        root = ET.fromstring(metadata)
    except Exception:
        logger.warning("Failed to collect SAML metadata for Okta app %s", app_id, exc_info=True)
        return {}

    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    sso_url = None
    for node in root.findall(".//md:SingleSignOnService", namespace):
        location = node.attrib.get("Location")
        binding = node.attrib.get("Binding")
        # Prefer the HTTP-POST SSO endpoint when metadata exposes multiple bindings.
        if location and (
            sso_url is None or binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ):
            sso_url = location

    result = {}
    if root.attrib.get("entityID"):
        result["saml_metadata_entity_id"] = root.attrib["entityID"]
    if sso_url:
        result["saml_metadata_sso_url"] = sso_url
    return result


@app.transformer(name="application_jwks", columns=ApplicationJWKS, parallelized=True)
def application_jwks(application: Application, ctx: SourceContext):
    oauth_client = application.settings.oauth_client
    if oauth_client and oauth_client.jwks:
        for key in oauth_client.jwks.keys:
            yield {
                "app_id": application.id,
                "app_name": application.name,
                **key.model_dump(),
            }


@app.transformer(
    name="application_group_push_mappings",
    columns=ApplicationGroupMapping,
    parallelized=True,
)
def application_group_push_mappings(application: Application, ctx: SourceContext):
    if "GROUP_PUSH" in application.features:
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/group-push/mappings"
        ):
            for item in page:
                yield {"app_id": application.id, "app_name": application.name, **item}


@app.transformer(
    name="application_secrets", columns=ApplicationSecrets, parallelized=True
)
def application_secrets(application: Application, ctx: SourceContext):
    oauth_client = application.credentials.oauth_client
    if (
        oauth_client
        and oauth_client.token_endpoint_auth_method == "client_secret_basic"
    ):
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/credentials/secrets"
        ):
            for item in page:
                yield {"app_id": application.id, "app_name": application.name, **item}


@app.transformer(name="application_users", columns=ApplicationUser, parallelized=True)
def application_users(application: Application, ctx: SourceContext):
    """DLT transformer, fetches users assigned to an Okta application via GET /apps/{applicationId}/users.

    Args:
        application (Application): Okta application record.
        ctx (SourceContext): SourceContext containing the REST client for API calls.

    Yields:
        _type_: _description_
    """
    for page in ctx.pool.paginate(f"/api/v1/apps/{application.id}/users"):
        for item in page:
            yield {
                "app_id": application.id,
                "app_features": application.features,
                "app_name": application.name,
                "app_label": application.label,
                "app_settings": application.settings.app,
                "app_sign_on_mode": application.sign_on_mode,
                **item,
            }


@app.transformer(
    name="saml_federation_providers",
    columns=SamlFederationProvider,
    parallelized=True,
)
def saml_federation_providers(application: Application):
    # Keep SAML row builders pure; DLT transformer boundaries recompute by design.
    row = saml_federation_provider_row(application)
    if row:
        yield row


@app.transformer(name="saml_issuers", columns=SamlIssuer, parallelized=True)
def saml_issuers(application: Application):
    row = saml_issuer_row(application)
    if row:
        yield row


@app.transformer(
    name="saml_assertion_consumer_services",
    columns=SamlAssertionConsumerService,
    parallelized=True,
)
def saml_assertion_consumer_services(application: Application):
    yield from saml_acs_rows(application)


@app.resource(name="client_applications", columns=ClientApplication, parallelized=True)
def client_applications(ctx: SourceContext):
    for page in ctx.pool.paginate("/oauth2/v1/clients"):
        for item in page:
            yield item


@app.transformer(
    name="client_role_assignments", columns=ClientRoleAssignment, parallelized=True
)
def client_role_assignments(client: ClientApplication, ctx: SourceContext):
    if client.application_type == "service":
        for page in ctx.pool.paginate(
            f"/oauth2/v1/clients/{client.client_id}/roles?expand=targets/catalog/apps&expand=targets/groups"
        ):
            for item in page:
                yield {"from_resource": "client", "source_id": client.client_id, **item}


@app.resource(name="built_in_roles", columns=BuiltInRole, parallelized=True)
def built_in_roles():
    """DLT resource, yields a static list of built-in Okta roles.

    Yields:
        role (Role): Okta built-in role record.
    """

    for role in BUILT_IN_ROLES:
        yield {"type": role}


@app.resource(
    name="user_role_assignments", columns=UserRoleAssignment, parallelized=True
)
def user_role_assignments(ctx: SourceContext):
    @app.defer
    def _assignee_details(user_id: str):
        try:
            user_details = ctx.pool.paginate(
                f"/api/v1/users/{user_id}/roles?expand=targets/catalog/apps&expand=targets/groups"
            )
            for roles in user_details:
                for role in roles:
                    yield {"from_resource": "user", "source_id": user_id, **role}

        except Exception as e:
            logger.error(
                f"Error in resource 'user_role_assignments' processing assignee_details: {e}",
                extra={"resource": "user_role_assignments", "phase": "defer"},
            )
            return

    for page in ctx.pool.paginate("/api/v1/iam/assignees/users"):
        for item in page:
            yield _assignee_details(item["id"])


@app.transformer(
    name="group_role_assignments", columns=GroupRoleAssignment, parallelized=True
)
def group_role_assignments(group: Group, ctx: SourceContext):
    if group.embedded.stats.has_admin_privilege:
        for page in ctx.pool.paginate(
            f"/api/v1/groups/{group.id}/roles?expand=targets/catalog/apps&expand=targets/groups"
        ):
            for role in page:
                yield {"from_resource": "group", "source_id": group.id, **role}


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


@app.resource(name="devices", columns=Device, parallelized=True)
def devices(ctx: SourceContext):
    """DLT resource, fetches Okta devices via GET /devices.

    Yields:
        device (Device): Device records.
    """
    for page in ctx.pool.paginate("/api/v1/devices?expand=userSummary"):
        yield page


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
        "CLIENT_UPDATE",
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


@app.resource(name="realms", columns=Realm, parallelized=True)
def realms(ctx: SourceContext):
    """DLT resource, fetches Okta realms via GET /api/v1/realms.

    Yields:
        realm (Realm): Realm records.
    """
    for page in ctx.pool.paginate("/api/v1/realms"):
        yield page


@app.resource(name="identity_providers", columns=IdentityProvider, parallelized=True)
def identity_providers(ctx: SourceContext):
    """DLT resource, fetches Okta identity providers via GET /api/v1/idps.

    Yields:
        identity_provider (IdentityProvider): Identity provider records.
    """
    for page in ctx.pool.paginate("/api/v1/idps"):
        for item in page:
            yield item


@app.transformer(name="identity_provider_users", columns=IDPUser, parallelized=True)
def identity_provider_users(idp: IdentityProvider, ctx: SourceContext):
    for page in ctx.pool.paginate(f"/api/v1/idps/{idp.id}/users"):
        for item in page:
            yield {
                "idp_id": idp.id,
                "idp_name": idp.name,
                "idp_type": idp.type,
                "idp_url": idp.idp_url,
                **item,
            }


@app.resource(name="authorization_servers", columns=AuthServer, parallelized=True)
def authorization_servers(ctx: SourceContext):
    """DLT resource, fetches Okta authorization servers via GET /api/v1/authorizationServers.

    Yields:
        authorization (AuthServer): AuthServer server records.
    """
    for page in ctx.pool.paginate("/api/v1/authorizationServers"):
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
    for agent in agent_pool.agents:
        yield {
            **agent.model_dump(),
            "agent_pool_name": agent_pool.name,
            "agent_type": agent_pool.type,
        }


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


@app.resource(name="api_tokens", columns=ApiToken, parallelized=True)
def api_tokens(ctx: SourceContext):
    """DLT resource, fetches Okta API tokens via GET /api/v1/api-tokens.

    Yields:
        api_token (ApiToken): API token records.
    """
    for page in ctx.pool.paginate("/api/v1/api-tokens"):
        yield page


@app.resource(name="api_services", columns=ApiService, parallelized=True)
def api_services(ctx: SourceContext):
    """DLT resource, fetches Okta API services via GET /api/v1/api-services.


    Yields:
        api_service (ApiService): API service records.
    """
    for page in ctx.pool.paginate("/integrations/api/v1/api-services"):
        yield page


@app.source(name="okta", max_table_nesting=0)
def source(
    credentials: Union[
        OktaAppCredentials, OktaEncodedAppCredentials, OktaTokenCredentials
    ] = dlt.secrets.value,
) -> tuple:
    """DLT source, defines Okta collection resources and transformers.

    Args:
        credentials: Okta API credentials based on key path, encoded key or SSWS for authentication.
    Returns:
        Tuple of DLT resources and transformers registered for Okta.
    """

    pool = ClientPool(
        base_url=credentials.base_url,
        auth=APIKeyAuth(
            name="Authorization", api_key=credentials.header, location="header"
        ),
        paginator=HeaderLinkPaginator(),
    )

    ctx = SourceContext(pool=pool)
    custom_roles_resource = custom_roles(ctx)
    built_in_roles_resource = built_in_roles()
    groups_resource = groups(ctx)
    applications_resource = applications(ctx)
    client_apps_resource = client_applications(ctx)
    agent_pools_resource = agent_pools(ctx)
    identity_providers_resource = identity_providers(ctx)
    policies_resource = policy_types | policies(ctx)
    resource_sets_resource = resource_sets(ctx)
    users_resource = users(ctx)
    return (
        organization(ctx),
        users_resource,
        groups_resource,
        groups_resource | group_memberships(ctx),
        groups_resource | group_assigned_apps(ctx),
        groups_resource | group_role_assignments(ctx),
        client_apps_resource,
        client_apps_resource | client_role_assignments(ctx),
        applications_resource,
        applications_resource | application_users(ctx),
        applications_resource | saml_federation_providers(),
        applications_resource | saml_issuers(),
        applications_resource | saml_assertion_consumer_services(),
        applications_resource | application_jwks(ctx),
        applications_resource | application_secrets(ctx),
        applications_resource | application_group_push_mappings(ctx),
        devices(ctx),
        policies_resource,
        policies_resource | policy_mappings(ctx),
        realms(ctx),
        identity_providers_resource,
        identity_providers_resource | identity_provider_users(ctx),
        authorization_servers(ctx),
        agent_pools_resource,
        agent_pools_resource | agents(),
        resource_sets_resource,
        resource_sets_resource | resources(ctx),
        custom_roles_resource,
        custom_roles_resource | custom_role_permissions(ctx),
        api_tokens(ctx),
        api_services(ctx),
        built_in_roles_resource,
        built_in_roles_resource | built_in_role_permissions,
        user_role_assignments(ctx),
    )
