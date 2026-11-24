"""Okta identities collection resources and helpers."""

import logging
from collections.abc import Iterator, Mapping

import requests
from dlt.extract import DltResource

from ..main import app
from ..models import Group, GroupMembership, PrivilegedUser, User, UserFactor
from ..source_context import (
    GROUPS_INITIAL_READ_TIMEOUT_MAX_ATTEMPTS,
    GROUPS_PAGE_SIZE_FALLBACK_DIVISORS,
    SourceContext,
)
from ..utils.http import InitialReadTimeoutBudget, OktaRetryExhaustedError
from .authorization import group_role_assignments, user_role_assignments

logger = logging.getLogger(__name__)


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


def all_resources(
    ctx: SourceContext, *, limit_user_mfa_collection: bool = False
) -> tuple[DltResource, ...]:
    """Compose identity pipelines, sharing memberships and per-source factor claims."""
    users_resource = users(ctx)
    groups_resource = groups(ctx)
    privileged_users_resource = privileged_users(ctx)
    group_memberships_resource = groups_resource | group_memberships(ctx)
    factor_resources: tuple[DltResource, ...]
    if limit_user_mfa_collection:
        factor_resources = (
            privileged_users_resource | user_factors(ctx),
            group_memberships_resource | admin_group_member_factors(ctx),
        )
    else:
        factor_resources = (users_resource | user_factors(ctx),)
    return (
        users_resource,
        groups_resource,
        group_memberships_resource,
        groups_resource | group_role_assignments(ctx),
        privileged_users_resource,
        privileged_users_resource | user_role_assignments(ctx),
        *factor_resources,
    )
