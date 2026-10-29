import fnmatch
import hashlib
import json
import logging
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Final
from urllib.parse import urlparse
from xml.etree.ElementTree import Element

import dlt
import requests
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from dlt.extract import DltResource
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator

from .main import app
from .models.application_users import ALWAYS_COLLECTED_APP_USERS
from .models import (
    Agent,
    AgentPool,
    ApiService,
    ApiServiceSecrets,
    ApiToken,
    Application,
    ApplicationGrant,
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
    PrivilegedUser,
    Realm,
    Resource,
    ResourceSet,
    ResourceSetRoleAssignment,
    SamlAccountResolutionField,
    SamlAccountResolutionRule,
    SamlAssertionConsumerService,
    SamlClaimMapping,
    SamlFederationProvider,
    SamlIssuer,
    SamlServiceProvider,
    SamlServiceProviderAssertionConsumerService,
    SamlTrustedIssuer,
    User,
    UserFactor,
    UserRoleAssignment,
)
from .models.application_users import (
    APPLICATION_USER_ITEM_SKIPPED_KEYS,
    APPLICATION_USER_PROFILE_SKIPPED_KEYS,
)
from .models.built_in_role import (
    BUILT_IN_ROLES,
    SUPPORTED_ROLE_ASSIGNMENT_TYPES,
    UNSUPPORTED_BUILT_IN_ROLES,
)
from .models.built_in_role_permission import BUILT_IN_PERMISSIONS
from .models.role_assignment import DIRECT_ASSIGNMENT_TYPES, GROUP_TARGETED_ROLE_TYPES
from .models.saml import (
    saml_account_resolution_field_row,
    saml_account_resolution_rule_row,
    saml_acs_rows,
    saml_claim_mapping_rows,
    saml_federation_provider_row,
    saml_issuer_row,
    saml_service_provider_row,
    saml_sp_acs_rows,
    saml_trusted_issuer_row,
)
from .telemetry import NullTelemetryRecorder, Telemetry
from .utils.auth import AnyOktaCredentials
from .utils.entra_tenant import EntraTenantIdResolver
from .utils.http import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    DEFAULT_ORG_CONCURRENCY,
    DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
    EndpointThrottle,
    InitialReadTimeoutBudget,
    OktaRESTClient,
    OktaRetryExhaustedError,
    OrgThrottle,
)

logger = logging.getLogger(__name__)

# One entry per Okta rate limit bucket the collector touches. Each family's
# EndpointThrottle paces itself from the X-Rate-Limit-* headers of its own
# responses, so a family must map to exactly one Okta bucket: two families on
# one bucket overshoot it, and one family across two buckets paces both from
# whichever headers arrived last. First fnmatch match wins and fnmatch's "*"
# matches "/" too, so narrower patterns precede broader ones. The per-minute
# values are what one org's Rate Limit Buckets table reported; they vary by
# org tier and are documentation only, the throttle never hard-codes them.
# An OAuth app is allocated 50% of each bucket by default, so the collector
# typically sees half of every value quoted here.
API_RATE_LIMIT_ENDPOINTS = [
    # Bucket /api/v1/users/{id:.+} READ (2000/min): every GET below /users/<id>,
    # that is factors, roles and role targets. The greedy {id:.+} template is
    # what separates these from the listing. The literal "/users/" keeps
    # "/api/v1/users" and "/api/v1/users?limit=..." out of this family.
    "/api/v1/users/*",
    # Bucket /api/v1/users (600/min): the users listing.
    "/api/v1/users*",
    # Bucket /api/v1/groups (500/min): listing, /groups/{id}/users, roles and
    # role targets. GET /api/v1/groups/{id} has its own bucket (1000/min) but
    # fnmatch cannot express "exactly one more segment"; it is folded in here
    # on purpose (one call per group push mapping, and pacing against the
    # smaller budget is the safe error).
    "/api/v1/groups*",
    # Bucket /api/v1/apps (100/min): the listing and every per-app sub-resource
    # (users, groups, grants, group push mappings, credentials, SAML metadata).
    # GET /api/v1/apps/{id} has its own bucket (500/min) but is never called;
    # {id} matches one segment, so /apps/{id}/users lands here (confirmed).
    "/api/v1/apps*",
    # Bucket /api/v1/iam (1600/min): roles, resource sets, assignees.
    "/api/v1/iam*",
    # Bucket /api/v1/devices (100/min): the devices listing.
    "/api/v1/devices*",
    # Bucket /oauth2/v1/clients (100/min): listing, roles and role targets.
    "/oauth2/v1/clients*",
    # API service integrations have their own bucket (100/min), undocumented
    # and absent from the Rate Limit Buckets table: api-services and their
    # secrets.
    "/integrations/*",
    # Bucket /api/v1 (1000/min): the catch-all for org, policies and their
    # mappings, realms, idps (listing, metadata.xml, users), authorization
    # servers, agent pools and API tokens. There is no idps bucket.
    "*",
]

# Families whose endpoints also serve SAML metadata as XML.
SAML_METADATA_FAMILIES: Final = ("/api/v1/apps*", "*")


def _is_direct_active_role_assignment(
    item: Mapping[str, object], from_resource: str
) -> bool:
    """Tell whether a role assignment is active, direct, and of a supported type.

    Args:
        item: Role assignment record from Okta.
        from_resource: Principal kind the assignment belongs to: user, group, or client.

    Returns:
        True if the assignment should be collected.
    """
    return (
        item.get("status") == "ACTIVE"
        and item.get("assignmentType") == DIRECT_ASSIGNMENT_TYPES.get(from_resource)
        and item.get("type") in SUPPORTED_ROLE_ASSIGNMENT_TYPES
    )


def _last_href_path_segment(href: str | None) -> str | None:
    """Return the last path segment of a link href, or None if there is none.

    Args:
        href: Link URL from an Okta _links entry.
    """
    if not href:
        return None

    path = urlparse(href).path.rstrip("/")
    return path.rsplit("/", 1)[-1] if path else None


def _resource_set_binding_assignee_id(member: Mapping[str, object]) -> str | None:
    """Extract the assignee id from a resource set binding member's self link.

    Args:
        member: Binding member record from Okta.

    Returns:
        The id from the member's self link, or None if the link is missing.
    """
    links = member.get("_links")
    if not isinstance(links, Mapping):
        return None

    link = links.get("self")
    if isinstance(link, Mapping):
        return _last_href_path_segment(link.get("href"))

    return None


def _role_assignment_base_path(from_resource: str, source_id: str) -> str:
    """Build the roles collection path for a principal.

    Args:
        from_resource: Principal kind: user, group, or client.
        source_id: The principal's id.

    Returns:
        The Okta API path listing the principal's role assignments.
    """
    if from_resource == "client":
        return f"/oauth2/v1/clients/{source_id}/roles"
    return f"/api/v1/{from_resource}s/{source_id}/roles"


def _role_assignment_scope(
    item: Mapping[str, object],
    from_resource: str,
    source_id: str,
    ctx: "SourceContext",
) -> dict[str, list[object]]:
    """Fetch the targets a scoped role assignment is limited to.

    Only APP_ADMIN assignments (app targets) and group-targeted role types carry
    a scope. Fetch errors other than retry exhaustion are logged and yield none.

    Args:
        item: Role assignment record from Okta.
        from_resource: Principal kind: user, group, or client.
        source_id: The principal's id.
        ctx: Source context providing the client pool.

    Returns:
        {"scope_apps": [...]} or {"scope_groups": [...]}, or {} when unscoped.
    """
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


APPLICATION_GRANTS_ACCESS_DENIED_LIMIT: Final[int] = 10
"""Consecutive access-denied (403) responses after which application OAuth 2.0
grant collection is abandoned for all remaining applications."""

# Okta returns 20 applications per page unless asked; 200 is its maximum.
APPLICATIONS_PAGE_SIZE = 200
APPLICATION_USERS_PAGE_SIZE = 500
GROUPS_PAGE_SIZE = 200
GROUPS_PAGE_SIZE_FALLBACK_DIVISORS = (1, 2, 4)
GROUPS_INITIAL_READ_TIMEOUT_MAX_ATTEMPTS = 2
APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE = 20
APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE = 200
GROUP_PUSH_MAPPINGS_PAGE_SIZE = 1000
IDENTITY_PROVIDER_USERS_PAGE_SIZE = 200


class ClientPool:
    """REST clients for the Okta org, one per endpoint family.

    Each family has its own EndpointThrottle pacing requests from the rate limit
    headers of its own Okta bucket; all throttles share one org-wide in-flight
    gate. A request is routed to its family by matching the path against
    API_RATE_LIMIT_ENDPOINTS.
    """

    def __init__(
        self,
        base_url: str,
        auth,
        paginator,
        throttle_factory: Callable[..., EndpointThrottle] = EndpointThrottle,
        endpoint_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
        org_concurrency: int = DEFAULT_ORG_CONCURRENCY,
        rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
        rate_limit_remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
        telemetry: Telemetry | None = None,
    ):
        """Create the throttles and clients for every endpoint family.

        Args:
            base_url: Okta org base URL.
            auth: requests auth applied to every request.
            paginator: dlt paginator following Link headers.
            throttle_factory: Builds a throttle per family; tests substitute fakes.
            endpoint_concurrency: Maximum in-flight requests per family.
            org_concurrency: Maximum in-flight requests across all families.
            rate_limit_max_elapsed_seconds: Retry budget for a request stuck on 429.
            rate_limit_remaining_reserve: Requests kept as headroom in each window.
            telemetry: Collection telemetry recorder, or None to disable.
        """
        self._telemetry = telemetry or NullTelemetryRecorder()
        # One org throttle per source, shared by every endpoint family's
        # throttle: the in-flight permit gate and the org-wide outage backoff.
        org_throttle = OrgThrottle(org_concurrency)
        throttles = {
            pattern: throttle_factory(
                max_concurrency=endpoint_concurrency,
                remaining_reserve=rate_limit_remaining_reserve,
                org_throttle=org_throttle,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        self._clients: dict[str, RESTClient] = {
            pattern: OktaRESTClient(
                base_url=base_url,
                headers={"accept": "application/json"},
                auth=auth,
                paginator=paginator,
                endpoint_family=pattern,
                throttle=throttles[pattern],
                rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
                telemetry=self._telemetry,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        # SAML metadata is XML; one client per family that serves it, sharing
        # that family's throttle.
        self._saml_metadata_clients: dict[str, RESTClient] = {
            pattern: OktaRESTClient(
                base_url=base_url,
                headers={"accept": "application/xml"},
                auth=auth,
                paginator=paginator,
                endpoint_family=pattern,
                throttle=throttles[pattern],
                rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
                telemetry=self._telemetry,
            )
            for pattern in SAML_METADATA_FAMILIES
        }

    @staticmethod
    def _endpoint_family(path: str) -> str:
        """Map a request path to its endpoint family pattern.

        Args:
            path: Request path, possibly with a query string.

        Returns:
            The first matching pattern in API_RATE_LIMIT_ENDPOINTS, else "*".
        """
        for pattern in API_RATE_LIMIT_ENDPOINTS:
            if fnmatch.fnmatch(path, pattern):
                return pattern
        return "*"

    def get_client(self, path: str) -> RESTClient:
        """Return the JSON client for the path's endpoint family.

        Args:
            path: Request path.
        """
        return self._clients[self._endpoint_family(path)]

    def paginate(self, path: str, **kwargs):
        """Paginate a path through its family's client, recording pages in telemetry.

        Args:
            path: Request path.
            **kwargs: Passed to the client's paginate, such as params or data_selector.

        Yields:
            Each page of items.
        """
        for page in self.get_client(path).paginate(path, **kwargs):
            try:
                row_count = len(page)
            except TypeError:
                row_count = None
            self._telemetry.record_page(path, row_count)
            yield page

    def get(self, path: str, **kwargs):
        """Issue a single GET through the path's family client.

        Args:
            path: Request path.
            **kwargs: Passed to the client's get.

        Returns:
            The response.
        """
        return self.get_client(path).get(path, **kwargs)

    def get_saml_metadata(self, path: str):
        """Fetch SAML metadata XML through the path's family client.

        Args:
            path: Metadata path of an application or identity provider.

        Returns:
            The response with XML content.
        """
        return self._saml_metadata_clients[self._endpoint_family(path)].get(path)


class ConsecutiveAccessDeniedBreaker:
    """Trips after an uninterrupted run of access-denied (403) responses.

    Least-privilege collector roles cannot read some per-object endpoints at
    all, so once every request in a row is denied there is no point in issuing
    one request per remaining object. Only a successful request disproves the
    missing permission and resets the run, so callers must not record outcomes
    that carry no permission signal (such as a 404 for a deleted object);
    those neither count nor reset. Once tripped, the breaker never resets.
    The breaker is thread-safe.

    Attributes:
        tripped: Whether the denial limit has been reached and callers should
            stop issuing further requests.
    """

    def __init__(self, limit: int) -> None:
        """Create a breaker that trips at the given denial limit.

        Args:
            limit: Number of consecutive access-denied responses that trips
                the breaker. Must be at least 1.

        Raises:
            ValueError: If limit is less than 1.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self._limit: int = limit
        self._lock: Lock = Lock()
        self._consecutive_denials: int = 0
        self._tripped: bool = False

    @property
    def tripped(self) -> bool:
        """Whether the breaker has tripped and requests should stop.

        Returns:
            True once record_access_denied has counted the limit of
            consecutive denials, False otherwise.
        """
        with self._lock:
            return self._tripped

    def record_success(self) -> None:
        """Reset the consecutive denial count after a successful request."""
        with self._lock:
            self._consecutive_denials = 0

    def record_access_denied(self) -> bool:
        """Count one access-denied response toward the limit.

        Returns:
            True when this denial is the one that trips the breaker, False
            when the breaker was already tripped or the limit has not been
            reached yet.
        """
        with self._lock:
            if self._tripped:
                return False
            self._consecutive_denials += 1
            if self._consecutive_denials >= self._limit:
                self._tripped = True
                return True
            return False


class UserFactorClaims:
    """Grants each user's factor fetch to exactly one of the parallel streams.

    Attributes:
        _claimed: User IDs whose factor fetch has already been granted.
        _lock: Guards _claimed against the parallelized transformer threads.
    """

    def __init__(self) -> None:
        """Start with no claimed users."""
        self._claimed: set[str] = set()
        self._lock = threading.Lock()

    def claim(self, user_id: str) -> bool:
        """Atomically claim the factor fetch for a user.

        Args:
            user_id: Okta user ID to claim.

        Returns:
            True if this caller should fetch the user's factors,
            False if another stream already claimed the user.
        """
        with self._lock:
            if user_id in self._claimed:
                return False
            self._claimed.add(user_id)
            return True


@dataclass
class SourceContext:
    """Context for Okta API operations.

    Attributes:
        pool: Client pool used to issue Okta API requests.
        tenant_domain: Casefolded hostname of the collected Okta tenant.
        telemetry: Collection-phase telemetry recorder.
        application_grants_breaker: Shared breaker that stops application
            OAuth 2.0 grant collection after consecutive access-denied
            responses.
        user_factor_claims: Shared registry granting each user's factor fetch
            to one of the factor streams.
        applications_page_size: Applications requested per applications page.
        application_users_page_size: Users requested per application-users
            page.
        groups_page_size: Groups requested per expanded groups page.
        application_group_assignments_page_size: Groups requested per
            application page.
        group_push_mappings_page_size: Mappings requested per group-push page.
        identity_provider_users_page_size: Users requested per
            identity-provider page.
    """

    pool: ClientPool
    tenant_domain: str
    telemetry: Telemetry = field(default_factory=NullTelemetryRecorder)
    application_grants_breaker: ConsecutiveAccessDeniedBreaker = field(
        default_factory=lambda: ConsecutiveAccessDeniedBreaker(
            APPLICATION_GRANTS_ACCESS_DENIED_LIMIT
        )
    )
    user_factor_claims: UserFactorClaims = field(default_factory=UserFactorClaims)
    applications_page_size: int = APPLICATIONS_PAGE_SIZE
    application_users_page_size: int = APPLICATION_USERS_PAGE_SIZE
    groups_page_size: int = GROUPS_PAGE_SIZE
    application_group_assignments_page_size: int = (
        APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    )
    group_push_mappings_page_size: int = GROUP_PUSH_MAPPINGS_PAGE_SIZE
    identity_provider_users_page_size: int = IDENTITY_PROVIDER_USERS_PAGE_SIZE


def _group_page_sizes(initial_page_size: int) -> tuple[int, ...]:
    """Page sizes to try for the groups listing, largest first.

    Args:
        initial_page_size: Configured page size.

    Returns:
        Distinct sizes from GROUPS_PAGE_SIZE_FALLBACK_DIVISORS, each at least 1.
    """
    return tuple(
        dict.fromkeys(
            max(initial_page_size // divisor, 1)
            for divisor in GROUPS_PAGE_SIZE_FALLBACK_DIVISORS
        )
    )


def _is_read_timeout_retry_exhaustion(error: OktaRetryExhaustedError) -> bool:
    """Tell whether retry exhaustion came from read timeouts rather than HTTP errors.

    Args:
        error: The exhaustion error.
    """
    return error.context.status_code is None and isinstance(
        error.__cause__, requests.exceptions.ReadTimeout
    )


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


# Authentication factor collection
#
# Enumerating factors costs one GET /api/v1/users/{id}/factors request per
# user. By default every user in the users listing is covered
# (users | user_factors). With limit_user_mfa_collection enabled only
# privileged users are, discovered by two parallel streams:
#   1. users with direct role assignments (privileged_users | user_factors)
#   2. members of groups whose stats report hasAdminPrivilege, chained off the
#      membership rows already being collected so no member list is paginated
#      twice (groups | group_memberships | admin_group_member_factors, a
#      renamed clone of user_factors fed through admin_group_members)
# A user can appear in both streams (e.g. a direct super admin who is also in
# several admin groups), and dlt transformers cannot consume a merged,
# deduplicated stream, so both share ctx.user_factor_claims: whichever stream
# claims a user ID first fetches the factors, later claimants skip. For every
# claimed user with zero factors a scope-marker row (NULL factor id) is
# written, so downstream the authentication_factors node property can
# distinguish:
#   NULL - user not covered (factors never fetched)
#   0    - user covered, no factors usable for MFA
#   N    - user covered, N factors in ACTIVE status
# (see OktaLookup.user_authentication_factors_count and
# descriptions/nodes/Okta_User.md).
def user_factor_rows(user_id: str, ctx: SourceContext) -> Iterator[dict[str, object]]:
    """Fetch one user's enrolled factors via GET /api/v1/users/{id}/factors.

    A failed fetch is logged and yields nothing at all (not even the scope
    marker), so the user's authentication_factors node property stays NULL
    ("not collected") instead of understating the factor count. Rate-limit
    retry exhaustion is re-raised to stop the transformer.

    Args:
        user_id: Okta user ID whose factors to enumerate.
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        One user_factors row per enrolled factor, or a single scope-marker row
        holding only user_id (NULL factor id) when the user has no factors, so
        a collected user without factors (0) stays distinct from a user whose
        factors were never fetched (NULL on the node).
    """
    try:
        rows = [
            {"user_id": user_id, **item}
            for page in ctx.pool.paginate(f"/api/v1/users/{user_id}/factors")
            for item in page
        ]
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            "Error fetching authentication factors for user %s: %s",
            user_id,
            e,
            extra={"resource": "user_factors", "phase": "defer"},
        )
        return
    yield from rows or [{"user_id": user_id}]


def admin_group_members(membership: Mapping[str, object]) -> Iterator[PrivilegedUser]:
    """Narrow a group_memberships row to its member when the group holds admin privilege.

    Prepended to the admin-group clone of user_factors as a dlt yield-map step,
    so the transformer sees the same id-only user records as the direct
    privileged-user stream.

    Args:
        membership: A group_memberships row (carries group_has_admin_privilege).

    Yields:
        The member as a PrivilegedUser, or nothing for non-admin groups.
    """
    member_id = membership.get("id")
    if membership.get("group_has_admin_privilege") and isinstance(member_id, str):
        yield PrivilegedUser(id=member_id)


# The transformer and its limited-mode clone replace the shared user_factors
# table so each collection is a fresh snapshot: appended leftovers from an
# earlier run would inflate counts and let a user whose fetch failed inherit
# stale rows. table_name is explicit so the renamed clone keeps loading there.
@app.transformer(
    name="user_factors",
    table_name="user_factors",
    columns=UserFactor,
    parallelized=True,
    write_disposition="replace",
)
def user_factors(
    user: User | PrivilegedUser, ctx: SourceContext
) -> Iterator[dict[str, object]]:
    """DLT transformer, fetches a user's factors unless another stream claimed them.

    Chained off users (full collection) or, with limit_user_mfa_collection,
    off privileged_users and, as a renamed clone, off admin-group memberships.

    Args:
        user: User record carrying the Okta user ID.
        ctx: SourceContext containing the REST client and the claims registry.

    Yields:
        user_factor (UserFactor): Enrolled factor or scope-marker record.
    """
    if ctx.user_factor_claims.claim(user.id):
        yield from user_factor_rows(user.id, ctx)


def admin_group_member_factors(ctx: SourceContext) -> DltResource:
    """Limited-mode factor transformer for admin-group members.

    A renamed clone of user_factors meant to be piped from group_memberships;
    the prepended admin_group_members step narrows each membership row to its
    member, or drops it for non-admin groups.

    Args:
        ctx: SourceContext shared with the user_factors transformer.

    Returns:
        The unpiped clone, still loading to the user_factors table.
    """
    # Rename before piping: with_name() on a piped transformer would clone the
    # parent pipe too and paginate every member list a second time.
    # insert_at=0 prepends the step so it filters the transformer's input.
    return (
        user_factors(ctx)
        .with_name("admin_group_member_factors")
        .add_yield_map(admin_group_members, insert_at=0)
    )


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
    page_sizes = _group_page_sizes(ctx.groups_page_size)
    for index, page_size in enumerate(page_sizes):
        pages = iter(
            ctx.pool.paginate(
                "/api/v1/groups?expand=stats",
                params={"limit": page_size},
                initial_read_timeout_budget=InitialReadTimeoutBudget(
                    GROUPS_INITIAL_READ_TIMEOUT_MAX_ATTEMPTS
                ),
            )
        )
        try:
            first_page = next(pages)
        except StopIteration:
            return
        except OktaRetryExhaustedError as error:
            has_fallback = index + 1 < len(page_sizes)
            if not has_fallback or not _is_read_timeout_retry_exhaustion(error):
                raise
            logger.warning(
                "Retrying expanded Okta group collection with smaller page size "
                "after initial read timeout previous_page_size=%s next_page_size=%s "
                "url=%s",
                page_size,
                page_sizes[index + 1],
                error.context.url,
            )
            continue

        for item in first_page:
            yield item
        for page in pages:
            for item in page:
                yield item
        return

    # dlt.current.resource_state()["last_run"] = str(datetime.now().isoformat())


@app.transformer(
    name="group_memberships",
    columns=GroupMembership,
    parallelized=True,
    write_disposition="replace",
)
def group_memberships(group: Group, ctx: SourceContext) -> Iterator[dict[str, object]]:
    """DLT transformer, fetches group members via GET /groups/{groupId}/users.

    Args:
        group: Okta group record whose members to fetch.
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        membership (GroupMembership): Member ID and login with group_id and
            group_has_admin_privilege, the latter consumed by the limited-mode
            factor stream (see admin_group_members). The rest of the member's
            user record is dropped: nothing reads it here and it is already
            collected by the users resource, so keeping it would multiply the
            largest table by the size of a user object.
    """
    if group.embedded.stats.users_count > 0:
        for page in ctx.pool.paginate(f"/api/v1/groups/{group.id}/users"):
            for item in page:
                profile = item.get("profile") or {}
                yield {
                    "id": item.get("id"),
                    "login": profile.get("login"),
                    "group_id": group.id,
                    # Carried along so the limited-mode factor stream
                    # (admin_group_members) can select admin-group members
                    # without paginating the member list a second time.
                    "group_has_admin_privilege": (
                        group.embedded.stats.has_admin_privilege
                    ),
                }


def _application_group_assignment_fingerprint(
    assignment: Mapping[str, object],
) -> str:
    """Return a type-preserving canonical fingerprint for duplicate evidence."""
    evidence = {
        "assignment_last_updated": assignment.get("lastUpdated"),
        "assignment_priority": assignment.get("priority"),
        "assignment_profile": assignment.get("profile"),
    }
    try:
        canonical_evidence = json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "application-group assignment has non-JSON duplicate evidence"
        ) from exc

    return hashlib.sha256(canonical_evidence.encode("utf-8")).hexdigest()


def application_group_assignment_rows(application: Application, ctx: SourceContext):
    """Stream authoritative assignments while retaining compact duplicate state."""
    assignment_fingerprints: dict[str, str] = {}
    duplicate_count = 0

    for page in ctx.pool.paginate(
        f"/api/v1/apps/{application.id}/groups",
        params={"limit": ctx.application_group_assignments_page_size},
    ):
        for assignment in page:
            if not isinstance(assignment, Mapping):
                raise ValueError(
                    "application-group assignment without a usable group ID "
                    f"for application {application.id}"
                )

            group_id = assignment.get("id")
            if not isinstance(group_id, str) or not group_id.strip():
                raise ValueError(
                    "application-group assignment without a usable group ID "
                    f"for application {application.id}"
                )
            group_id = group_id.strip()
            fingerprint = _application_group_assignment_fingerprint(assignment)

            row = {
                "id": application.id,
                "group_id": group_id,
                "name": application.name,
                "label": application.label,
                "status": application.status,
                "lastUpdated": application.last_updated,
                "app_sign_on_mode": application.sign_on_mode,
                "assignment_last_updated": assignment.get("lastUpdated"),
                "assignment_priority": assignment.get("priority"),
                "assignment_profile": assignment.get("profile"),
            }
            previous = assignment_fingerprints.get(group_id)
            if previous is None:
                assignment_fingerprints[group_id] = fingerprint
                yield row
            elif previous == fingerprint:
                duplicate_count += 1
            else:
                raise ValueError(
                    "conflicting application-group assignments for "
                    f"application {application.id} and group {group_id}"
                )

    if duplicate_count:
        logger.warning(
            "deduplicated %d identical application-group assignment rows for application %s",
            duplicate_count,
            application.id,
            extra={"resource": "group_assigned_apps", "phase": "collect"},
        )


# This authoritative transformer and its shared parent use DLT directly so
# OpenHound's best-effort wrapper cannot publish a partial replacement snapshot.
@dlt.transformer(
    name="group_assigned_apps",
    columns=GroupAssignedApp,
    parallelized=True,
    write_disposition="replace",
)
def group_assigned_apps(application: Application, ctx: SourceContext):
    """Fetch authoritative group assignments for an Okta application."""
    try:
        yield from application_group_assignment_rows(application, ctx)
    except Exception:
        logger.error(
            "authoritative application-group assignment collection failed",
            extra={"resource": "group_assigned_apps", "phase": "resource_iteration"},
        )
        raise


app.dlt_resources.append(group_assigned_apps)


@dlt.resource(name="applications", columns=Application, parallelized=True)
def applications(ctx: SourceContext):
    """DLT resource, fetches Okta applications via GET /api/v1/apps.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        application (Application): Okta application record.
    """
    for page in ctx.pool.paginate(
        "/api/v1/apps", params={"limit": ctx.applications_page_size}
    ):
        for item in page:
            if item.get("signOnMode") == "SAML_2_0":
                item = {**item, **_saml_metadata_fields(ctx, item)}
            yield item


app.dlt_resources.append(applications)


def _saml_metadata_fields(
    ctx: SourceContext, application: dict[str, Any]
) -> dict[str, str]:
    """Read entity id and SSO URL from an application's SAML metadata.

    Args:
        ctx: Source context providing the client pool.
        application: Raw application record.

    Returns:
        saml_metadata_entity_id and saml_metadata_sso_url when present, preferring
        the HTTP-POST binding; {} when the app has no metadata link or it is
        unavailable.
    """
    metadata_link = (application.get("_links") or {}).get("metadata") or {}
    if not metadata_link.get("href"):
        return {}

    app_id = application.get("id")
    if not app_id:
        return {}

    root = _saml_metadata_root(
        ctx,
        f"/api/v1/apps/{app_id}/sso/saml/metadata",
        "app",
        app_id,
    )
    if root is None:
        return {}

    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    sso_url = None
    for node in root.findall(".//md:SingleSignOnService", namespace):
        location = node.attrib.get("Location")
        binding = node.attrib.get("Binding")
        # Prefer the HTTP-POST SSO endpoint when metadata exposes multiple bindings.
        if location and (
            sso_url is None
            or binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ):
            sso_url = location

    result = {}
    if root.attrib.get("entityID"):
        result["saml_metadata_entity_id"] = root.attrib["entityID"]
    if sso_url:
        result["saml_metadata_sso_url"] = sso_url
    return result


def _user_name_template_value(user_name_template: object) -> str | None:
    """Return the template string of a user name template, from a mapping or model.

    Args:
        user_name_template: Mapping or object with a template attribute.
    """
    if isinstance(user_name_template, Mapping):
        value = user_name_template.get("template")
        return value if isinstance(value, str) else None
    value = getattr(user_name_template, "template", None)
    return value if isinstance(value, str) else None


def _saml_metadata_root(
    ctx: SourceContext,
    path: str,
    object_kind: str,
    object_id: str,
) -> Element | None:
    """Fetch and parse SAML metadata XML for an Okta object.

    Args:
        ctx: Source context providing the client pool.
        path: Metadata path.
        object_kind: Object kind for log messages, such as "app".
        object_id: Object id for log messages.

    Returns:
        The XML root, or None when the metadata is forbidden, missing, or invalid.

    Raises:
        OktaRetryExhaustedError: If the request exhausted its retries.
        requests.HTTPError: For HTTP errors other than 403 and 404.
    """
    try:
        response = ctx.pool.get_saml_metadata(path)
        return ET.fromstring(response.content)
    except OktaRetryExhaustedError:
        logger.error(
            "Required SAML metadata request exhausted retries for Okta %s %s",
            object_kind,
            object_id,
            exc_info=True,
        )
        raise
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        if status_code not in {403, 404}:
            raise
        logger.warning(
            "SAML metadata is unavailable for Okta %s %s status=%s",
            object_kind,
            object_id,
            status_code,
        )
        return None
    except (ET.ParseError, DefusedXmlException):
        logger.warning(
            "Okta returned invalid SAML metadata XML for %s %s",
            object_kind,
            object_id,
            exc_info=True,
        )
        return None


def _saml_idp_metadata_fields(
    ctx: SourceContext,
    identity_provider: dict[str, Any],
) -> dict[str, Any]:
    """Read entity id and assertion consumer services from an IdP's SAML metadata.

    Args:
        ctx: Source context providing the client pool.
        identity_provider: Raw identity provider record.

    Returns:
        saml_metadata_entity_id and saml_metadata_acs_endpoints when present; {}
        when the IdP has no metadata link or it is unavailable.
    """
    metadata_link = (identity_provider.get("_links") or {}).get("metadata") or {}
    idp_id = identity_provider.get("id")
    if not metadata_link.get("href") or not idp_id:
        return {}

    root = _saml_metadata_root(
        ctx,
        f"/api/v1/idps/{idp_id}/metadata.xml",
        "identity provider",
        idp_id,
    )
    if root is None:
        return {}

    namespace = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
    endpoints = []
    for node in root.findall(
        ".//md:SPSSODescriptor/md:AssertionConsumerService",
        namespace,
    ):
        location = node.attrib.get("Location")
        if not location:
            continue
        raw_index = node.attrib.get("index")
        try:
            index = int(raw_index) if raw_index is not None else None
        except ValueError:
            index = None
        raw_default = node.attrib.get("isDefault")
        endpoints.append(
            {
                "url": location,
                "binding": node.attrib.get("Binding"),
                "index": index,
                "is_default": (
                    raw_default.casefold() == "true"
                    if raw_default is not None
                    else None
                ),
            }
        )

    result: dict[str, Any] = {}
    if root.attrib.get("entityID"):
        result["saml_metadata_entity_id"] = root.attrib["entityID"]
    if endpoints:
        result["saml_metadata_acs_endpoints"] = endpoints
    return result


@app.transformer(name="application_jwks", columns=ApplicationJWKS, parallelized=True)
def application_jwks(application: Application, ctx: SourceContext):
    """DLT transformer, yields an application's JWKs; see application_jwk_rows.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        JWK rows tagged with app_id and app_name.
    """
    yield from application_jwk_rows(application, ctx)


def _embedded_application_jwk_rows(application: Application):
    """Yield the JWKs embedded in the application's OAuth client settings.

    Args:
        application: Parent application record.

    Yields:
        One row per embedded key, tagged with app_id and app_name.
    """
    oauth_client = application.settings.oauth_client if application.settings else None
    if not oauth_client or not oauth_client.jwks:
        return

    for key in oauth_client.jwks.keys:
        yield {
            "app_id": application.id,
            "app_name": application.name,
            **key.model_dump(),
        }


def _jwk_page_items(page: object):
    """Extract the key list from a JWKS page in any of Okta's response shapes.

    Args:
        page: A page from the credentials/jwks endpoint.

    Returns:
        The keys list, or the page itself when it is already a list.
    """
    if isinstance(page, Mapping):
        keys = page.get("keys")
        if isinstance(keys, list):
            return keys
        jwks = page.get("jwks")
        if isinstance(jwks, Mapping) and isinstance(jwks.get("keys"), list):
            return jwks["keys"]
        return []
    return page


def application_jwk_rows(application: Application, ctx: SourceContext):
    """Yield an application's JWKs, preferring the API over the embedded copy.

    Only applications with embedded JWKs are queried. API errors other than 404
    are logged; on any error the embedded keys are yielded instead.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        JWK rows tagged with app_id and app_name.

    Raises:
        OktaRetryExhaustedError: If the request exhausted its retries.
    """
    embedded_rows = list(_embedded_application_jwk_rows(application))
    if not embedded_rows:
        return

    try:
        rows = []
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/credentials/jwks"
        ):
            for item in _jwk_page_items(page):
                if isinstance(item, Mapping):
                    rows.append(
                        {
                            "app_id": application.id,
                            "app_name": application.name,
                            **item,
                        }
                    )
        yield from rows or embedded_rows
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code != 404:
            logger.error(
                "Error fetching application JWKs for %s: %s",
                application.id,
                e,
                extra={"resource": "application_jwks", "phase": "defer"},
            )
        yield from embedded_rows


@app.transformer(name="application_grants", columns=ApplicationGrant)
def application_grants(
    application: Application, ctx: SourceContext
) -> Iterator[dict[str, Any]]:
    """DLT transformer, fetches OAuth 2.0 grants of an OIDC or service
    application via GET /apps/{applicationId}/grants.

    Reading app grants requires the Super Administrator role. Each
    access-denied (403) response is counted by the shared
    ctx.application_grants_breaker; once it trips, grant collection is skipped
    for all remaining applications without issuing further requests.

    Args:
        application: Okta application record.
        ctx: SourceContext containing the REST client and the grant breaker.

    Yields:
        grant (dict): Application grant record enriched with an ``app_id`` key.

    Raises:
        OktaRetryExhaustedError: If retries were exhausted for a grants
            request.
    """
    oauth_client = application.settings.oauth_client if application.settings else None
    if application.sign_on_mode != "OPENID_CONNECT" and not (
        oauth_client and oauth_client.application_type == "service"
    ):
        return

    breaker = ctx.application_grants_breaker
    if breaker.tripped:
        return

    try:
        for page in ctx.pool.paginate(f"/api/v1/apps/{application.id}/grants"):
            breaker.record_success()
            for item in page:
                yield {"app_id": application.id, **item}
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code == 403:
            if breaker.record_access_denied():
                logger.warning(
                    "Skipping app grant collection after %d consecutive "
                    "access-denied responses; oauth_scopes and OIDC "
                    "application attack path edges will be missing.",
                    APPLICATION_GRANTS_ACCESS_DENIED_LIMIT,
                    extra={"resource": "application_grants", "phase": "defer"},
                )
            else:
                logger.debug(
                    "Access denied fetching application grants for %s",
                    application.id,
                    extra={"resource": "application_grants", "phase": "defer"},
                )
        elif status_code != 404:
            logger.error(
                "Error fetching application grants for %s: %s",
                application.id,
                e,
                extra={"resource": "application_grants", "phase": "defer"},
            )


@app.transformer(
    name="application_group_push_mappings",
    columns=ApplicationGroupMapping,
    parallelized=True,
)
def application_group_push_mappings(application: Application, ctx: SourceContext):
    """DLT transformer, fetches group push mappings of GROUP_PUSH applications.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool and page size.

    Yields:
        Mapping rows with the target group name resolved.
    """
    if "GROUP_PUSH" in application.features:
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/group-push/mappings",
            params={"limit": ctx.group_push_mappings_page_size},
        ):
            for item in page:
                yield application_group_push_mapping_row(application, item, ctx)


def application_group_push_mapping_row(
    application: Application,
    mapping: Mapping[str, object],
    ctx: SourceContext,
) -> dict[str, object]:
    """Build a group push mapping row, adding the target group's name when readable.

    Args:
        application: Parent application record.
        mapping: Raw mapping record.
        ctx: Source context providing the client pool.

    Returns:
        The mapping tagged with app_id and app_name, plus target_group_name if
        the target group could be fetched.

    Raises:
        OktaRetryExhaustedError: If the group request exhausted its retries.
    """
    row = {"app_id": application.id, "app_name": application.name, **mapping}
    target_group_id = mapping.get("targetGroupId")
    if not isinstance(target_group_id, str):
        return row

    try:
        target_group = ctx.pool.get(f"/api/v1/groups/{target_group_id}").json()
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            "Error fetching target group %s for group push mapping %s: %s",
            target_group_id,
            mapping.get("id"),
            e,
            extra={"resource": "application_group_push_mappings", "phase": "defer"},
        )
        return row

    if not isinstance(target_group, Mapping):
        return row

    profile = target_group.get("profile")
    if not isinstance(profile, Mapping):
        return row

    target_group_name = profile.get("name")
    if isinstance(target_group_name, str) and target_group_name:
        row["target_group_name"] = target_group_name

    return row


@app.transformer(
    name="application_secrets", columns=ApplicationSecrets, parallelized=True
)
def application_secrets(application: Application, ctx: SourceContext):
    """DLT transformer, fetches client secrets of client_secret_basic applications.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    oauth_client = (
        application.credentials.oauth_client if application.credentials else None
    )
    if (
        oauth_client
        and oauth_client.token_endpoint_auth_method == "client_secret_basic"
    ):
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/credentials/secrets"
        ):
            for item in page:
                # Okta always returns the plaintext client_secret here and offers
                # no way to suppress it; secret_hash is enough to model the secret.
                yield {
                    "app_id": application.id,
                    "app_name": application.name,
                    **{k: v for k, v in item.items() if k != "client_secret"},
                }


@app.transformer(
    name="api_service_secrets", columns=ApiServiceSecrets, parallelized=True
)
def api_service_secrets(api_service: ApiService, ctx: SourceContext):
    """DLT transformer, fetches client secrets of API service integrations.

    Args:
        api_service: Parent API service integration record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    yield from api_service_secret_rows(api_service, ctx)


def api_service_secret_rows(api_service: ApiService, ctx: SourceContext):
    """Yield client secret rows for one API service integration.

    Args:
        api_service: Parent API service integration record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    for page in ctx.pool.paginate(
        f"/integrations/api/v1/api-services/{api_service.id}/credentials/secrets"
    ):
        for item in page:
            # Okta already redacts this value (e.g. "***************bHuy"), but it
            # is dropped anyway, matching the application secrets handling.
            yield {
                "app_id": api_service.id,
                "app_name": api_service.name,
                **{k: v for k, v in item.items() if k != "client_secret"},
            }


@app.transformer(name="application_users", columns=ApplicationUser, parallelized=True)
def application_users(application: Application, ctx: SourceContext):
    """DLT transformer, fetches users assigned to an Okta application via GET /apps/{applicationId}/users.

    Args:
        application (Application): Okta application record.
        ctx (SourceContext): SourceContext containing the REST client for API calls.

    Yields:
        _type_: _description_
    """
    yield from application_user_rows(application, ctx)


def application_user_rows(application: Application, ctx: SourceContext):
    """Yield user assignment rows for one application, tagged with app details.

    Records the stream outcome in telemetry and re-raises any failure.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool, page size, and telemetry.

    Yields:
        Assignment rows with app_* fields prepended.
    """
    row_count = 0
    telemetry = getattr(ctx, "telemetry", NullTelemetryRecorder())
    sign_on = application.settings.sign_on if application.settings else None
    user_name_template = (
        application.credentials.user_name_template if application.credentials else None
    )
    # Application details are the same on every row, so build them once.
    app_fields = {
        "app_id": application.id,
        "app_features": application.features,
        "app_name": application.name,
        "app_status": getattr(application, "status", None),
        "app_settings": application.settings.app if application.settings else None,
        "app_sign_on_mode": application.sign_on_mode,
        "app_subject_name_id_template": (
            sign_on.subject_name_id_template if sign_on else None
        ),
        "app_subject_name_id_format": (
            sign_on.subject_name_id_format if sign_on else None
        ),
        "app_user_name_template": _user_name_template_value(user_name_template),
    }
    try:
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/users",
            params={"limit": ctx.application_users_page_size},
        ):
            for item in page:
                row_count += 1
                yield {
                    **app_fields,
                    # Profile attributes nobody reads are dropped to save
                    # space: this is the largest collected table.
                    "profile": {
                        key: value
                        for key, value in (item.get("profile") or {}).items()
                        if key not in APPLICATION_USER_PROFILE_SKIPPED_KEYS
                    },
                    # Likewise the assignment timestamps, _links and _embedded
                    # copies are dropped; the trimmed profile above stays.
                    **{
                        key: value
                        for key, value in item.items()
                        if key not in APPLICATION_USER_ITEM_SKIPPED_KEYS
                        and key != "profile"
                    },
                }
    except Exception:
        telemetry.record_application_stream("failed")
        logger.error(
            "Application user collection failed app_id=%s rows_streamed=%s",
            application.id,
            row_count,
            exc_info=True,
        )
        raise
    telemetry.record_application_stream("completed")
    logger.info(
        "Application user collection completed app_id=%s rows=%s",
        application.id,
        row_count,
    )


def app_user_collection_filter(
    app_ids: frozenset[str],
) -> Callable[[Application], bool]:
    """Build the DLT item filter applied when application-user collection is limited.

    Args:
        app_ids: Okta application IDs collected in addition to ALWAYS_COLLECTED_APP_USERS.

    Returns:
        Predicate that keeps applications whose name is always collected or whose ID is listed.
    """

    def collects_app_users(application: Application) -> bool:
        return (
            application.name in ALWAYS_COLLECTED_APP_USERS or application.id in app_ids
        )

    return collects_app_users


@app.transformer(
    name="saml_federation_providers",
    columns=SamlFederationProvider,
    parallelized=True,
)
def saml_federation_providers(application: Application):
    # Keep SAML row builders pure; DLT transformer boundaries recompute by design.
    """DLT transformer, yields an application's SAML federation provider row.

    Args:
        application: Parent application record.

    Yields:
        At most one row.
    """
    row = saml_federation_provider_row(application)
    if row:
        yield row


@app.transformer(name="saml_issuers", columns=SamlIssuer, parallelized=True)
def saml_issuers(application: Application):
    """DLT transformer, yields an application's SAML issuer row.

    Args:
        application: Parent application record.

    Yields:
        At most one row.
    """
    row = saml_issuer_row(application)
    if row:
        yield row


@app.transformer(
    name="saml_assertion_consumer_services",
    columns=SamlAssertionConsumerService,
    parallelized=True,
)
def saml_assertion_consumer_services(application: Application):
    """DLT transformer, yields an application's SAML assertion consumer services.

    Args:
        application: Parent application record.

    Yields:
        One row per assertion consumer service.
    """
    yield from saml_acs_rows(application)


@app.transformer(
    name="saml_claim_mappings", columns=SamlClaimMapping, parallelized=True
)
def saml_claim_mappings(application: Application):
    """DLT transformer, yields an application's SAML claim mappings.

    Args:
        application: Parent application record.

    Yields:
        One row per claim mapping.
    """
    yield from saml_claim_mapping_rows(application)


@app.transformer(
    name="saml_service_providers",
    columns=SamlServiceProvider,
    parallelized=True,
)
def saml_service_providers(identity_provider: IdentityProvider, ctx: SourceContext):
    """DLT transformer, yields an inbound IdP's SAML service provider row.

    Args:
        identity_provider: Parent identity provider record.
        ctx: Source context providing the tenant domain.

    Yields:
        At most one row.
    """
    row = saml_service_provider_row(identity_provider, ctx.tenant_domain)
    if row:
        yield row


@app.transformer(
    name="saml_account_resolution_rules",
    columns=SamlAccountResolutionRule,
    parallelized=True,
)
def saml_account_resolution_rules(identity_provider: IdentityProvider):
    """DLT transformer, yields an IdP's SAML account resolution rule row.

    Args:
        identity_provider: Parent identity provider record.

    Yields:
        At most one row.
    """
    row = saml_account_resolution_rule_row(identity_provider)
    if row:
        yield row


@app.transformer(
    name="saml_account_resolution_fields",
    columns=SamlAccountResolutionField,
    parallelized=True,
)
def saml_account_resolution_fields(identity_provider: IdentityProvider):
    """DLT transformer, yields an IdP's SAML account resolution field row.

    Args:
        identity_provider: Parent identity provider record.

    Yields:
        At most one row.
    """
    row = saml_account_resolution_field_row(identity_provider)
    if row:
        yield row


@app.transformer(
    name="saml_trusted_issuers", columns=SamlTrustedIssuer, parallelized=True
)
def saml_trusted_issuers(identity_provider: IdentityProvider, ctx: SourceContext):
    """DLT transformer, yields an IdP's SAML trusted issuer row.

    Args:
        identity_provider: Parent identity provider record.
        ctx: Source context providing the tenant domain.

    Yields:
        At most one row.
    """
    row = saml_trusted_issuer_row(identity_provider, ctx.tenant_domain)
    if row:
        yield row


@app.transformer(
    name="saml_sp_assertion_consumer_services",
    columns=SamlServiceProviderAssertionConsumerService,
    parallelized=True,
)
def saml_sp_assertion_consumer_services(identity_provider: IdentityProvider):
    """DLT transformer, yields an IdP's service provider assertion consumer services.

    Args:
        identity_provider: Parent identity provider record.

    Yields:
        One row per assertion consumer service.
    """
    yield from saml_sp_acs_rows(identity_provider)


@app.resource(name="client_applications", columns=ClientApplication, parallelized=True)
def client_applications(ctx: SourceContext):
    """DLT resource, fetches OAuth 2.0 clients via GET /oauth2/v1/clients.

    Args:
        ctx: Source context providing the client pool.

    Yields:
        client (ClientApplication): Client application record.
    """
    for page in ctx.pool.paginate("/oauth2/v1/clients"):
        for item in page:
            yield item


@app.transformer(
    name="client_role_assignments", columns=ClientRoleAssignment, parallelized=True
)
def client_role_assignments(client: ClientApplication, ctx: SourceContext):
    """DLT transformer, fetches direct active role assignments of service clients.

    Args:
        client: Parent client application record.
        ctx: Source context providing the client pool.

    Yields:
        Role assignment rows with from_resource, source_id, and any scope targets.
    """
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


@app.resource(name="privileged_users", columns=PrivilegedUser, parallelized=True)
def privileged_users(ctx: SourceContext):
    """DLT resource, fetches admin role holders via GET /api/v1/iam/assignees/users.

    Args:
        ctx: Source context providing the client pool.

    Yields:
        user (PrivilegedUser): Privileged user record.
    """
    for page in ctx.pool.paginate("/api/v1/iam/assignees/users"):
        for item in page:
            yield item


@app.transformer(
    name="user_role_assignments", columns=UserRoleAssignment, parallelized=True
)
def user_role_assignments(user: PrivilegedUser, ctx: SourceContext):
    """DLT transformer, fetches a privileged user's direct active role assignments.

    Errors other than retry exhaustion are logged and end the user's rows.

    Args:
        user: Parent privileged user record.
        ctx: Source context providing the client pool.

    Yields:
        Role assignment rows; see user_role_assignment_rows.
    """
    try:
        yield from user_role_assignment_rows(user.id, ctx)
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            f"Error in resource 'user_role_assignments' processing assignee_details: {e}",
            extra={"resource": "user_role_assignments", "phase": "defer"},
        )
        return


def user_role_assignment_rows(user_id: str, ctx: SourceContext):
    """Yield a user's direct active role assignments with their scope targets.

    Args:
        user_id: The user's id.
        ctx: Source context providing the client pool.

    Yields:
        Role assignment rows with from_resource, source_id, and any scope targets.
    """
    for roles in ctx.pool.paginate(f"/api/v1/users/{user_id}/roles"):
        for role in roles:
            if _is_direct_active_role_assignment(role, "user"):
                yield {
                    "from_resource": "user",
                    "source_id": user_id,
                    **role,
                    **_role_assignment_scope(role, "user", user_id, ctx),
                }


@app.transformer(
    name="group_role_assignments", columns=GroupRoleAssignment, parallelized=True
)
def group_role_assignments(group: Group, ctx: SourceContext):
    """DLT transformer, fetches direct active role assignments of admin groups.

    Args:
        group: Parent group record.
        ctx: Source context providing the client pool.

    Yields:
        Role assignment rows with from_resource, source_id, and any scope targets.
    """
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
    """DLT resource, yields the policy types whose policies are collected.

    Yields:
        {"policy_type": type} for each collected type.
    """
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
        "SESSION_VIOLATION_DETECTION",
        "CLIENT_UPDATE",
        # Early Access; orgs without the feature answer 400 for this type.
        "IDENTITY_CLAIM_SOURCING",
    ]
    for policy_type in okta_policies:
        yield {"policy_type": policy_type}


@app.transformer(name="policies", columns=Policy, parallelized=True)
def policies(policy: dict, ctx: SourceContext):
    """DLT resource, fetches Okta policies via GET /policies.

    A policy type the org does not support (for example an Early Access type
    that is not enabled) answers 400; that type is logged as a warning and
    skipped so the remaining types are still collected. Other HTTP errors
    propagate.

    Yields:
        policy (Policy): Policy records.
    """
    policy_type = policy["policy_type"]
    try:
        for page in ctx.pool.paginate("/api/v1/policies", params={"type": policy_type}):
            for item in page:
                yield item
    except requests.HTTPError as e:
        status_code = getattr(e.response, "status_code", None)
        if status_code != 400:
            raise
        try:
            # e.g. E0000002 "The request was not valid: Invalid policy type
            # specified. Missing Required Feature Flag SUPPORT_FOR_REAUTH_WITH_EXTERNAL_IDP"
            body = e.response.json()
            detail = f"{body.get('errorCode')} {body.get('errorSummary')}"
        except (ValueError, AttributeError):
            detail = str(e)
        logger.warning(
            "Skipping policy type %s, which is not available in this org: %s",
            policy_type,
            detail,
            extra={"resource": "policies", "phase": "collect"},
        )


@app.transformer(name="policy_mappings", columns=PolicyMapping, parallelized=True)
def policy_mappings(policy: Policy, ctx: SourceContext):
    """DLT transformer, fetches a policy's resource mappings via GET /policies/{id}/mappings.

    Args:
        policy: Parent policy record.
        ctx: Source context providing the client pool.

    Yields:
        Mapping rows tagged with policy_id.
    """
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
            protocol = item.get("protocol") or {}
            if item.get("type") == "SAML2" and protocol.get("type") == "SAML2":
                item = {**item, **_saml_idp_metadata_fields(ctx, item)}
            yield _redact_idp_client_secret(item)


def _redact_idp_client_secret(item: dict[str, Any]) -> dict[str, Any]:
    # Okta returns the plaintext client_secret of OIDC and social identity
    # providers under protocol.credentials.client; only client_id is modeled.
    protocol = item.get("protocol")
    if not isinstance(protocol, dict):
        return item
    credentials = protocol.get("credentials")
    if not isinstance(credentials, dict):
        return item
    client = credentials.get("client")
    if not isinstance(client, dict) or "client_secret" not in client:
        return item
    return {
        **item,
        "protocol": {
            **protocol,
            "credentials": {
                **credentials,
                "client": {k: v for k, v in client.items() if k != "client_secret"},
            },
        },
    }


@app.transformer(name="identity_provider_users", columns=IDPUser, parallelized=True)
def identity_provider_users(idp: IdentityProvider, ctx: SourceContext):
    """DLT transformer, fetches users linked to an IdP via GET /idps/{id}/users.

    Args:
        idp: Parent identity provider record.
        ctx: Source context providing the client pool and page size.

    Yields:
        Linked user rows with idp_* fields prepended.
    """
    for page in ctx.pool.paginate(
        f"/api/v1/idps/{idp.id}/users",
        params={"limit": ctx.identity_provider_users_page_size},
    ):
        for item in page:
            subject = (idp.policy.subject or {}) if idp.policy else {}
            user_name_template = subject.get("userNameTemplate") or {}
            yield {
                "idp_id": idp.id,
                "idp_name": idp.name,
                "idp_type": idp.type,
                "idp_protocol_type": getattr(
                    getattr(idp, "protocol", None),
                    "type",
                    None,
                ),
                "idp_status": idp.status,
                "idp_url": idp.idp_url,
                "idp_subject_user_name_template": user_name_template.get("template"),
                "idp_subject_match_type": subject.get("matchType"),
                "idp_subject_filter": subject.get("filter"),
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
    """DLT transformer, fetches a resource set's resources via GET /resource-sets/{id}/resources.

    Args:
        resource_set: Parent resource set record.
        ctx: Source context providing the client pool.

    Yields:
        Resource rows tagged with resource_set_id.
    """
    for page in ctx.pool.paginate(
        f"/api/v1/iam/resource-sets/{resource_set.id}/resources"
    ):
        for item in page:
            yield {"resource_set_id": resource_set.id, **item}


@app.transformer(
    name="resource_set_role_assignments",
    columns=ResourceSetRoleAssignment,
    parallelized=True,
)
def resource_set_role_assignments(resource_set: ResourceSet, ctx: SourceContext):
    """DLT transformer, fetches the members bound to each role of a resource set.

    Members without an assignee link are skipped with a warning.

    Args:
        resource_set: Parent resource set record.
        ctx: Source context providing the client pool.

    Yields:
        Member rows tagged with resource_set_id, role_id, and assignee_id.
    """
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


@app.resource(name="api_services", columns=ApiService, parallelized=True)
def api_services(ctx: SourceContext) -> Iterator[dict[str, Any]]:
    """DLT resource, fetches Okta API service integrations via
    GET /integrations/api/v1/api-services.

    Listing API service integrations requires the Super Administrator role.
    An access-denied (403) response is logged as a warning and treated as an
    empty listing; all other HTTP errors propagate.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        api_service (ApiService): API service integration records.
    """
    try:
        for page in ctx.pool.paginate("/integrations/api/v1/api-services"):
            for item in page:
                yield item
    except requests.HTTPError as e:
        status_code = getattr(e.response, "status_code", None)
        if status_code != 403:
            raise
        logger.warning(
            "Access denied listing API service integrations; skipping them.",
            extra={"resource": "api_services", "phase": "collect"},
        )


@app.source(name="okta", max_table_nesting=0)
def source(
    credentials: AnyOktaCredentials = dlt.secrets.value,
    applications_page_size: int = APPLICATIONS_PAGE_SIZE,
    application_users_page_size: int = APPLICATION_USERS_PAGE_SIZE,
    groups_page_size: int = GROUPS_PAGE_SIZE,
    application_group_assignments_page_size: int = (
        APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    ),
    group_push_mappings_page_size: int = GROUP_PUSH_MAPPINGS_PAGE_SIZE,
    identity_provider_users_page_size: int = IDENTITY_PROVIDER_USERS_PAGE_SIZE,
    limit_app_user_collection: bool = False,
    app_user_collection_app_ids: list[str] | None = None,
    limit_user_mfa_collection: bool = False,
    endpoint_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    org_concurrency: int = DEFAULT_ORG_CONCURRENCY,
    rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    rate_limit_remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
    telemetry: Telemetry | None = None,
) -> tuple:
    """DLT source, defines Okta collection resources and transformers.

    Args:
        credentials: Okta API credentials: a service app private key (file
            path or base64), an API Service Integration client secret, or an
            SSWS API token.
        applications_page_size: Applications requested per applications page.
        application_users_page_size: Users requested per application-users page.
        groups_page_size: Groups requested per expanded groups page.
        application_group_assignments_page_size: Groups requested per application page.
        group_push_mappings_page_size: Mappings requested per group-push page.
        identity_provider_users_page_size: Users requested per identity-provider page.
        limit_app_user_collection: Collect application users only for the app types in
            ALWAYS_COLLECTED_APP_USERS and the applications in app_user_collection_app_ids.
        app_user_collection_app_ids: Additional Okta application IDs whose users are collected
            when limit_app_user_collection is enabled.
        limit_user_mfa_collection: Collect MFA factors only for privileged users
            (direct role assignees and admin-group members) instead of every user.
        endpoint_concurrency: Maximum simultaneous requests for each endpoint family.
        org_concurrency: Maximum simultaneous requests across all endpoint families.
        rate_limit_max_elapsed_seconds: Maximum retry window for an individual 429 request.
        rate_limit_remaining_reserve: Requests retained as headroom in each observed window.
        telemetry: Internal collection-phase telemetry recorder.
    Returns:
        Tuple of DLT resources and transformers registered for Okta.
    """

    if not 1 <= application_users_page_size <= APPLICATION_USERS_PAGE_SIZE:
        raise ValueError(
            "application_users_page_size must be between 1 and "
            f"{APPLICATION_USERS_PAGE_SIZE}"
        )
    if not 1 <= groups_page_size <= GROUPS_PAGE_SIZE:
        raise ValueError(f"groups_page_size must be between 1 and {GROUPS_PAGE_SIZE}")
    if not (
        APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE
        <= application_group_assignments_page_size
        <= APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    ):
        raise ValueError(
            "application_group_assignments_page_size must be between "
            f"{APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE} and "
            f"{APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE}"
        )
    if not 1 <= applications_page_size <= APPLICATIONS_PAGE_SIZE:
        raise ValueError(
            f"applications_page_size must be between 1 and {APPLICATIONS_PAGE_SIZE}"
        )
    if not 1 <= group_push_mappings_page_size <= GROUP_PUSH_MAPPINGS_PAGE_SIZE:
        raise ValueError(
            "group_push_mappings_page_size must be between 1 and "
            f"{GROUP_PUSH_MAPPINGS_PAGE_SIZE}"
        )
    if not 1 <= identity_provider_users_page_size <= IDENTITY_PROVIDER_USERS_PAGE_SIZE:
        raise ValueError(
            "identity_provider_users_page_size must be between 1 and "
            f"{IDENTITY_PROVIDER_USERS_PAGE_SIZE}"
        )
    if endpoint_concurrency < 1:
        raise ValueError("endpoint_concurrency must be at least 1")
    if org_concurrency < 1:
        raise ValueError("org_concurrency must be at least 1")
    if rate_limit_max_elapsed_seconds <= 0:
        raise ValueError("rate_limit_max_elapsed_seconds must be positive")
    if rate_limit_remaining_reserve < 0:
        raise ValueError("rate_limit_remaining_reserve cannot be negative")

    telemetry = telemetry or NullTelemetryRecorder()
    telemetry.set_effective_settings(
        {
            "applications_page_size": applications_page_size,
            "application_users_page_size": application_users_page_size,
            "groups_page_size": groups_page_size,
            "application_group_assignments_page_size": (
                application_group_assignments_page_size
            ),
            "group_push_mappings_page_size": group_push_mappings_page_size,
            "identity_provider_users_page_size": identity_provider_users_page_size,
            "limit_app_user_collection": limit_app_user_collection,
            "app_user_collection_app_id_count": len(app_user_collection_app_ids or ()),
            "limit_user_mfa_collection": limit_user_mfa_collection,
            "endpoint_concurrency": endpoint_concurrency,
            "org_concurrency": org_concurrency,
            "rate_limit_max_elapsed_seconds": rate_limit_max_elapsed_seconds,
            "rate_limit_remaining_reserve": rate_limit_remaining_reserve,
        }
    )

    pool = ClientPool(
        base_url=credentials.base_url,
        auth=credentials.request_auth(),
        paginator=HeaderLinkPaginator(),
        endpoint_concurrency=endpoint_concurrency,
        org_concurrency=org_concurrency,
        rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
        rate_limit_remaining_reserve=rate_limit_remaining_reserve,
        telemetry=telemetry,
    )

    ctx = SourceContext(
        pool=pool,
        tenant_domain=credentials.tenant_domain,
        telemetry=telemetry,
        applications_page_size=applications_page_size,
        application_users_page_size=application_users_page_size,
        groups_page_size=groups_page_size,
        application_group_assignments_page_size=(
            application_group_assignments_page_size
        ),
        group_push_mappings_page_size=group_push_mappings_page_size,
        identity_provider_users_page_size=identity_provider_users_page_size,
    )
    custom_roles_resource = custom_roles(ctx)
    built_in_roles_resource = built_in_roles()
    groups_resource = groups(ctx)
    applications_resource = applications(ctx).add_map(EntraTenantIdResolver().enrich)
    client_apps_resource = client_applications(ctx)
    agent_pools_resource = agent_pools(ctx)
    api_services_resource = api_services(ctx)
    identity_providers_resource = identity_providers(ctx)
    policies_resource = policy_types | policies(ctx)
    resource_sets_resource = resource_sets(ctx)
    users_resource = users(ctx)
    privileged_users_resource = privileged_users(ctx)
    group_memberships_resource = groups_resource | group_memberships(ctx)
    application_users_resource = applications_resource | application_users(ctx)
    if limit_app_user_collection:
        application_users_resource.add_filter(
            app_user_collection_filter(frozenset(app_user_collection_app_ids or ())),
            insert_at=0,
        )

    factor_resources: tuple[DltResource, ...]
    if limit_user_mfa_collection:
        factor_resources = (
            privileged_users_resource | user_factors(ctx),
            group_memberships_resource | admin_group_member_factors(ctx),
        )
    else:
        factor_resources = (users_resource | user_factors(ctx),)
    return (
        organization(ctx),
        users_resource,
        groups_resource,
        group_memberships_resource,
        groups_resource | group_role_assignments(ctx),
        client_apps_resource,
        client_apps_resource | client_role_assignments(ctx),
        applications_resource,
        applications_resource | group_assigned_apps(ctx),
        applications_resource | application_grants(ctx),
        application_users_resource,
        applications_resource | saml_federation_providers(),
        applications_resource | saml_issuers(),
        applications_resource | saml_assertion_consumer_services(),
        applications_resource | saml_claim_mappings(),
        applications_resource | application_jwks(ctx),
        applications_resource | application_secrets(ctx),
        applications_resource | application_group_push_mappings(ctx),
        devices(ctx),
        policies_resource,
        policies_resource | policy_mappings(ctx),
        realms(ctx),
        identity_providers_resource,
        identity_providers_resource | saml_service_providers(ctx),
        identity_providers_resource | saml_account_resolution_rules(),
        identity_providers_resource | saml_account_resolution_fields(),
        identity_providers_resource | saml_trusted_issuers(ctx),
        identity_providers_resource | saml_sp_assertion_consumer_services(),
        identity_providers_resource | identity_provider_users(ctx),
        authorization_servers(ctx),
        agent_pools_resource,
        agent_pools_resource | agents(),
        resource_sets_resource,
        resource_sets_resource | resources(ctx),
        resource_sets_resource | resource_set_role_assignments(ctx),
        custom_roles_resource,
        custom_roles_resource | custom_role_permissions(ctx),
        api_tokens(ctx),
        api_services_resource,
        api_services_resource | api_service_secrets(ctx),
        built_in_roles_resource,
        built_in_roles_resource | built_in_role_permissions,
        privileged_users_resource,
        privileged_users_resource | user_role_assignments(ctx),
        *factor_resources,
    )
