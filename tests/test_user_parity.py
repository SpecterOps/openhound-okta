from typing import cast

import pytest

from openhound_okta.models import PrivilegedUser, User
from openhound_okta.models.user import UserProperties
from openhound_okta.source import (
    ClientPool,
    SourceContext,
    UserFactorClaims,
    admin_group_member_factor_rows,
    privileged_user_factor_rows,
)


class StubLookup:
    """In-memory OktaLookup replacement returning canned per-user answers.

    Attributes:
        _has_role_assignments: Canned answer for has_role_assignments().
    """

    def __init__(self, *, has_role_assignments: bool = False) -> None:
        self._has_role_assignments = has_role_assignments

    def org_id(self) -> str:
        """Return a fixed organization ID.

        Returns:
            The canned organization ID "org-1".
        """
        return "org-1"

    def has_role_assignments(self, principal_id: str, principal_type: str) -> bool:
        """Return the canned role-assignment answer for the test user.

        Args:
            principal_id: Must be the test user "user-1".
            principal_type: Must be "user".

        Returns:
            The has_role_assignments value passed to the constructor.
        """
        assert principal_id == "user-1"
        assert principal_type == "user"
        return self._has_role_assignments


def make_user(
    *,
    has_role_assignments: bool = False,
    authentication_factors_count: int | None = None,
    **overrides: object,
) -> User:
    """Build a validated test User wired to a StubLookup.

    Args:
        has_role_assignments: Canned lookup answer for the user's role flag.
        authentication_factors_count: Preprocessed factor count carried on the user
            row (None means the user's factors were never collected).
        **overrides: Raw API fields overriding the default user payload.

    Returns:
        A User model with _lookup and _extras injected for node generation.
    """
    user = User.model_validate(
        {
            "id": "user-1",
            "created": "2026-01-01T00:00:00Z",
            "status": "ACTIVE",
            "authentication_factors_count": authentication_factors_count,
            "profile": {
                "login": "alice@example.com",
                "displayName": "Alice Example",
                "email": "alice@example.com",
                "firstName": "Alice",
                "lastName": "Example",
            },
            **overrides,
        }
    )
    user._lookup = StubLookup(has_role_assignments=has_role_assignments)
    user._extras = {"tenant": "example.okta.com"}
    return user


def test_user_node_emits_core_oktahound_equivalent_properties() -> None:
    """The user node carries the core properties expected by OktaHound parity."""
    user = make_user(has_role_assignments=True, authentication_factors_count=3)

    properties = user.as_node.properties

    assert isinstance(properties, UserProperties)
    assert properties.name == "ALICE@EXAMPLE.COM"
    assert properties.displayname == "Alice Example"
    assert properties.okta_domain == "example.okta.com"
    assert properties.has_role_assignments is True
    assert properties.authentication_factors == 3
    assert properties.enabled is True


def test_unprivileged_user_node_has_null_authentication_factors() -> None:
    """An unprivileged user's authentication_factors property stays None."""
    user = make_user(has_role_assignments=False, authentication_factors_count=None)

    properties = user.as_node.properties

    assert isinstance(properties, UserProperties)
    assert properties.authentication_factors is None


def test_user_node_falls_back_to_login_when_display_name_is_missing() -> None:
    """The node display name falls back to the login without a displayName."""
    user = make_user(profile={"login": "alice@example.com"})

    assert user.as_node.properties.displayname == "alice@example.com"


class FactorStubPool:
    """ClientPool stand-in serving canned pages and recording request paths.

    Attributes:
        paths: Every paginated path, in call order, for request-count asserts.
        _factors_by_user: Factor rows returned per user ID.
        _members_by_group: Member rows returned per group ID.
        _groups: Group rows returned for the groups listing.
    """

    def __init__(
        self,
        factors_by_user: dict[str, list[dict[str, object]]] | None = None,
        members_by_group: dict[str, list[dict[str, object]]] | None = None,
        groups: list[dict[str, object]] | None = None,
    ) -> None:
        self.paths: list[str] = []
        self._factors_by_user = factors_by_user or {}
        self._members_by_group = members_by_group or {}
        self._groups = groups or []

    def paginate(self, path: str, **kwargs: object) -> list[list[dict[str, object]]]:
        """Return the canned single page matching the requested path.

        Args:
            path: Okta API path (groups listing, group members, or factors).
            **kwargs: Ignored pagination options accepted for compatibility.

        Returns:
            A one-page list of rows for the addressed groups listing, group's
            members, or user's factors.
        """
        self.paths.append(path)
        if path.startswith("/api/v1/groups?"):
            return [self._groups]
        if path.endswith("/factors"):
            user_id = path.split("/")[-2]
            return [self._factors_by_user.get(user_id, [])]
        group_id = path.split("/")[-2]
        return [self._members_by_group.get(group_id, [])]


class FactorStubContext:
    """Minimal SourceContext stand-in exposing only the client pool.

    Attributes:
        pool: The FactorStubPool serving canned API responses.
    """

    def __init__(self, pool: FactorStubPool) -> None:
        self.pool = pool


def make_stub_context(pool: FactorStubPool) -> SourceContext:
    """Build a FactorStubContext typed as the SourceContext it stands in for.

    Args:
        pool: The stub pool the context should expose.

    Returns:
        The stub context, cast to SourceContext for the factor-row helpers.
    """
    return cast(SourceContext, FactorStubContext(pool))


def make_membership(
    group_id: str, member_id: str, *, admin: bool = True
) -> dict[str, object]:
    """Build a group_memberships row as the chained factor transformer sees it.

    Args:
        group_id: Group the membership belongs to.
        member_id: Okta user ID of the member.
        admin: Value of the row's group_has_admin_privilege flag.

    Returns:
        A membership row dict with the fields the factor transformer reads.
    """
    return {
        "group_id": group_id,
        "group_has_admin_privilege": admin,
        "id": member_id,
    }


def test_user_factors_fetched_once_for_multi_path_privileged_user() -> None:
    """A direct super admin who is also in 3 admin groups gets one factors call."""
    pool = FactorStubPool(
        factors_by_user={"user-1": [{"id": "factor-1", "factorType": "token"}]},
    )
    ctx = make_stub_context(pool)
    claims = UserFactorClaims()

    rows = list(privileged_user_factor_rows(PrivilegedUser(id="user-1"), ctx, claims))
    for group_id in ("group-1", "group-2", "group-3"):
        rows.extend(
            admin_group_member_factor_rows(
                make_membership(group_id, "user-1"), ctx, claims
            )
        )

    assert rows == [{"user_id": "user-1", "id": "factor-1", "factorType": "token"}]
    assert pool.paths.count("/api/v1/users/user-1/factors") == 1


def test_admin_group_member_factors_skips_non_admin_group_members() -> None:
    """Members of non-admin groups trigger no factor requests at all."""
    pool = FactorStubPool()
    ctx = make_stub_context(pool)
    claims = UserFactorClaims()

    assert not list(
        admin_group_member_factor_rows(
            make_membership("group-1", "user-1", admin=False), ctx, claims
        )
    )
    assert pool.paths == []


def test_factorless_privileged_user_emits_scope_marker_row() -> None:
    """A privileged user without factors yields the user_id-only marker row."""
    pool = FactorStubPool(factors_by_user={})
    ctx = make_stub_context(pool)
    claims = UserFactorClaims()

    rows = list(privileged_user_factor_rows(PrivilegedUser(id="user-1"), ctx, claims))

    assert rows == [{"user_id": "user-1"}]


def test_failed_factor_fetch_yields_nothing_so_user_reads_as_uncollected() -> None:
    """A mid-pagination failure yields no rows at all, not a partial count."""

    class FailingPool:
        """Pool whose factors pagination fails after the first page."""

        def paginate(self, path: str) -> object:
            yield [{"id": "factor-1"}]
            raise RuntimeError("second page failed")

    class FailingContext:
        pool = FailingPool()

    rows = list(
        privileged_user_factor_rows(
            PrivilegedUser(id="user-1"),
            cast(SourceContext, FailingContext()),
            UserFactorClaims(),
        )
    )

    assert rows == []


def test_factor_fetch_rate_limit_exhaustion_propagates() -> None:
    """Rate-limit retry exhaustion is re-raised instead of being swallowed."""
    from openhound_okta.utils.http import OktaRetryContext, OktaRetryExhaustedError

    error = OktaRetryExhaustedError(
        OktaRetryContext(
            endpoint_family="/api/v1/users/*/factors",
            url="https://example.okta.com/api/v1/users/user-1/factors",
            status_code=429,
            attempts=5,
        )
    )

    class ExhaustedPool:
        """Pool whose factors pagination exhausts its rate-limit retries."""

        def paginate(self, path: str) -> object:
            raise error
            yield  # pragma: no cover - makes this a generator

    class ExhaustedContext:
        pool = ExhaustedPool()

    with pytest.raises(OktaRetryExhaustedError):
        list(
            privileged_user_factor_rows(
                PrivilegedUser(id="user-1"),
                cast(SourceContext, ExhaustedContext()),
                UserFactorClaims(),
            )
        )


def test_factor_requests_use_a_dedicated_throttle_family() -> None:
    """Factor calls must not share the users listing's throttle budget."""
    from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator

    pool = ClientPool(
        base_url="https://example.okta.com",
        auth=None,
        paginator=HeaderLinkPaginator(),
    )

    factors_client = pool.get_client("/api/v1/users/00u1/factors")

    assert factors_client is pool.get_client("/api/v1/users/00u2/factors")
    assert factors_client is not pool.get_client("/api/v1/users")
    assert factors_client is not pool.get_client("/api/v1/users/00u1/roles")


def make_member(user_id: str) -> dict[str, object]:
    """Build a minimal valid group-member row for the memberships endpoint.

    Args:
        user_id: Okta user ID of the member.

    Returns:
        A member row dict satisfying the GroupMembership model validation.
    """
    return {"id": user_id, "profile": {"login": f"{user_id}@example.com"}}


def make_group_item(
    group_id: str, *, admin: bool, users_count: int
) -> dict[str, object]:
    """Build a minimal valid group row for the expanded groups listing.

    Args:
        group_id: Okta group ID.
        admin: Value of the embedded hasAdminPrivilege stat.
        users_count: Value of the embedded usersCount stat.

    Returns:
        A group row dict satisfying the Group model validation.
    """
    return {
        "id": group_id,
        "created": "2026-01-01T00:00:00Z",
        "type": "OKTA_GROUP",
        "profile": {"name": group_id},
        "_embedded": {
            "stats": {
                "usersCount": users_count,
                "appsCount": 0,
                "hasAdminPrivilege": admin,
            }
        },
    }


def test_chained_factor_extraction_paginates_each_member_list_once() -> None:
    """groups | group_memberships | admin_group_member_factors shares one fetch.

    Extracts the real chained pipeline over a stub pool and asserts that each
    member list is paginated exactly once, factors are fetched once per
    admin-group member and never for non-admin-group members, and the
    factorless member yields the scope-marker row.
    """
    from dlt.common.schema import Schema
    from dlt.extract import DltSource

    from openhound_okta.source import (
        admin_group_member_factors,
        group_memberships,
        groups,
    )

    pool = FactorStubPool(
        groups=[
            make_group_item("admin-group", admin=True, users_count=2),
            make_group_item("plain-group", admin=False, users_count=1),
        ],
        members_by_group={
            "admin-group": [make_member("user-1"), make_member("user-2")],
            "plain-group": [make_member("user-3")],
        },
        factors_by_user={"user-1": [{"id": "factor-1"}]},
    )
    ctx = SourceContext(pool=cast(ClientPool, pool), tenant_domain="example.okta.com")
    groups_resource = groups(ctx)
    memberships_resource = groups_resource | group_memberships(ctx)
    factors_resource = memberships_resource | admin_group_member_factors(
        ctx, UserFactorClaims()
    )
    source = DltSource(
        Schema("okta_test"),
        "okta_test",
        [groups_resource, memberships_resource, factors_resource],
    )

    rows = list(source)

    assert pool.paths.count("/api/v1/groups/admin-group/users") == 1
    assert pool.paths.count("/api/v1/groups/plain-group/users") == 1
    assert pool.paths.count("/api/v1/users/user-1/factors") == 1
    assert pool.paths.count("/api/v1/users/user-2/factors") == 1
    assert "/api/v1/users/user-3/factors" not in pool.paths
    factor_rows = {
        row["user_id"]: row["id"]
        for row in rows
        if isinstance(row, dict) and "user_id" in row
    }
    assert factor_rows == {
        "user-1": "factor-1",
        "user-2": None,  # scope marker: collected, but no enrolled factors
    }
