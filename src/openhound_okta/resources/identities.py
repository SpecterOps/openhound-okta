"""User, group, membership and privileged factor collection."""

import logging
import threading
from collections.abc import Iterator, Mapping

import requests
from dlt.extract.resource import DltResource

from openhound_okta.main import app
from openhound_okta.models import (
    Group,
    GroupMembership,
    PrivilegedUser,
    User,
    UserFactor,
)
from openhound_okta.source_context import (
    GROUPS_PAGE_SIZE_FALLBACK_DIVISORS,
    SourceContext,
)
from openhound_okta.utils.http import OktaRetryExhaustedError

from .authorization import group_role_assignments, user_role_assignments

logger = logging.getLogger(__name__)


def _group_page_sizes(initial_page_size: int) -> tuple[int, ...]:
    return tuple(
        dict.fromkeys(
            max(initial_page_size // divisor, 1)
            for divisor in GROUPS_PAGE_SIZE_FALLBACK_DIVISORS
        )
    )


def _is_read_timeout_retry_exhaustion(error: OktaRetryExhaustedError) -> bool:
    return error.context.status_code is None and isinstance(
        error.__cause__, requests.exceptions.ReadTimeout
    )


@app.resource(name="users", columns=User, parallelized=True)
def users(ctx: SourceContext):
    """DLT resource, fetches Okta users via GET /users.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        Pages of Okta user records.
    """
    for page in ctx.pool.paginate("/api/v1/users"):
        yield page


# Authentication factor collection
#
# Enumerating factors costs one GET /api/v1/users/{id}/factors request per
# user, so factors are only collected for privileged users, discovered by two
# parallel streams:
#   1. users with direct role assignments (privileged_users | user_factors)
#   2. members of groups whose stats report hasAdminPrivilege, chained off the
#      membership rows already being collected so no member list is paginated
#      twice (groups | group_memberships | admin_group_member_factors)
# Both write to the user_factors table. A user can appear in both streams
# (e.g. a direct super admin who is also in several admin groups), and dlt
# transformers cannot consume a merged, deduplicated stream, so both
# transformers share one UserFactorClaims instance (created per source() call):
# whichever stream claims a user ID first fetches the factors, later claimants
# skip. For every claimed user with zero factors a scope-marker row (NULL
# factor id) is written, so downstream the authentication_factors node
# property can distinguish:
#   NULL - user not covered (not privileged, factors never fetched)
#   0    - user covered, no factors usable for MFA
#   N    - user covered, N factors in ACTIVE status
# (see OktaLookup.user_authentication_factors_count and
# descriptions/nodes/Okta_User.md).
class UserFactorClaims:
    """Grants each user's factor fetch to exactly one of the parallel streams.

    Attributes:
        _claimed: User IDs whose factor fetch has already been granted.
        _lock: Guards _claimed against the parallelized transformer threads.
    """

    def __init__(self) -> None:
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


# Both factor writers replace the shared user_factors table so each collection
# is a fresh snapshot: appended leftovers from an earlier run would inflate
# counts and let a user whose fetch failed inherit stale rows.
@app.transformer(
    name="user_factors",
    columns=UserFactor,
    parallelized=True,
    write_disposition="replace",
)
def user_factors(
    user: PrivilegedUser, ctx: SourceContext, claims: UserFactorClaims
) -> Iterator[dict[str, object]]:
    """DLT transformer, fetches factors of directly privileged users.

    Args:
        user: User returned by Okta's privileged assignee inventory endpoint.
        ctx: SourceContext containing the REST client for API calls.
        claims: Fetch-once registry shared with admin_group_member_factors.

    Yields:
        user_factor (UserFactor): Enrolled factor or scope-marker record.
    """
    if claims.claim(user.id):
        yield from user_factor_rows(user.id, ctx)


@app.transformer(
    name="admin_group_member_factors",
    table_name="user_factors",
    columns=UserFactor,
    parallelized=True,
    write_disposition="replace",
)
def admin_group_member_factors(
    membership: Mapping[str, object], ctx: SourceContext, claims: UserFactorClaims
) -> Iterator[dict[str, object]]:
    """DLT transformer, fetches factors of admin-group members.

    Chained off group_memberships so member lists are not paginated twice;
    writes to the same user_factors table as the user_factors transformer.

    Args:
        membership: A group_memberships row (carries group_has_admin_privilege).
        ctx: SourceContext containing the REST client for API calls.
        claims: Fetch-once registry shared with user_factors.

    Yields:
        user_factor (UserFactor): Enrolled factor or scope-marker record.
    """
    member_id = membership.get("id")
    if (
        membership.get("group_has_admin_privilege")
        and isinstance(member_id, str)
        and claims.claim(member_id)
    ):
        yield from user_factor_rows(member_id, ctx)


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
    """Fetch group members via GET /groups/{groupId}/skinny_users.

    Args:
        group: Okta group record whose members to fetch.
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        membership (GroupMembership): Member record enriched with group_id and
            group_has_admin_privilege, the latter consumed by the chained
            admin_group_member_factors transformer.
    """
    if group.embedded.stats.users_count > 0:
        for page in ctx.pool.paginate(f"/api/v1/groups/{group.id}/skinny_users"):
            for item in page:
                yield {
                    "group_id": group.id,
                    # Carried along so the chained admin_group_member_factors
                    # transformer can select admin-group members without
                    # paginating the member list a second time.
                    "group_has_admin_privilege": (
                        group.embedded.stats.has_admin_privilege
                    ),
                    **item,
                }


@app.resource(name="privileged_users", columns=PrivilegedUser, parallelized=True)
def privileged_users(ctx: SourceContext):
    for page in ctx.pool.paginate("/api/v1/iam/assignees/users"):
        for item in page:
            yield item


def all_resources(ctx: SourceContext) -> tuple[DltResource, ...]:
    """Compose identity pipelines with shared memberships and factor claims."""
    users_resource = users(ctx)
    groups_resource = groups(ctx)
    privileged_users_resource = privileged_users(ctx)
    factor_claims = UserFactorClaims()
    group_memberships_resource = groups_resource | group_memberships(ctx)
    return (
        users_resource,
        groups_resource,
        group_memberships_resource,
        group_memberships_resource | admin_group_member_factors(ctx, factor_claims),
        groups_resource | group_role_assignments(ctx),
        privileged_users_resource,
        privileged_users_resource | user_role_assignments(ctx),
        privileged_users_resource | user_factors(ctx, factor_claims),
    )
