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
        _authentication_factors_count: Canned answer for
            user_authentication_factors_count().
    """

    def __init__(
        self,
        *,
        has_role_assignments: bool = False,
        authentication_factors_count: int | None = None,
    ) -> None:
        self._has_role_assignments = has_role_assignments
        self._authentication_factors_count = authentication_factors_count

    def user_authentication_factors_count(self, user_id: str) -> int | None:
        """Return the canned factor count for the test user.

        Args:
            user_id: Must be the test user "user-1".

        Returns:
            The authentication_factors_count value passed to the constructor.
        """
        assert user_id == "user-1"
        return self._authentication_factors_count

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
        authentication_factors_count: Canned lookup answer for the
            preprocessed factor count (None means never collected).
        **overrides: Raw API fields overriding the default user payload.

    Returns:
        A User model with _lookup and _extras injected for node generation.
    """
    user = User.model_validate(
        {
            "id": "user-1",
            "created": "2026-01-01T00:00:00Z",
            "status": "ACTIVE",
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
    user._lookup = StubLookup(
        has_role_assignments=has_role_assignments,
        authentication_factors_count=authentication_factors_count,
    )
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


def test_user_lookup_distinguishes_uncollected_from_factorless_users() -> None:
    """The lookup counts ACTIVE factors, maps markers to 0 and absence to None."""
    import duckdb

    from openhound_okta.lookup import OktaLookup

    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute(
        "CREATE TABLE okta.user_factors (user_id VARCHAR, id VARCHAR, status VARCHAR)"
    )
    con.execute(
        "INSERT INTO okta.user_factors VALUES "
        "('user-1', 'factor-1', 'ACTIVE'), ('user-1', 'factor-2', 'ACTIVE'), "
        "('user-1', 'factor-3', 'PENDING_ACTIVATION'), "
        "('user-2', NULL, NULL), "
        "('user-4', 'factor-4', 'PENDING_ACTIVATION'), "
        "('user-5', 'factor-5', 'EXPIRED')"
    )

    lookup = OktaLookup(con)

    # Non-ACTIVE factors are not usable for MFA and are excluded.
    assert lookup.user_authentication_factors_count("user-1") == 2
    # Scope marker only: collected privileged user without factors.
    assert lookup.user_authentication_factors_count("user-2") == 0
    # Never collected: unprivileged user.
    assert lookup.user_authentication_factors_count("user-3") is None
    # Only unusable factors: reads as having no MFA.
    assert lookup.user_authentication_factors_count("user-4") == 0
    assert lookup.user_authentication_factors_count("user-5") == 0

    # Without a user_factors table every user reads as "not collected".
    empty_lookup = OktaLookup(duckdb.connect())
    assert empty_lookup.user_authentication_factors_count("user-1") is None


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


def test_factor_writers_replace_the_shared_table() -> None:
    """Both factor transformers snapshot user_factors per collection run."""
    from openhound_okta.source import admin_group_member_factors, user_factors

    claims = UserFactorClaims()

    assert user_factors(None, claims).write_disposition == "replace"
    assert admin_group_member_factors(None, claims).write_disposition == "replace"


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


def make_okta_user(user_id: str) -> dict[str, object]:
    """Build a minimal valid user row for the users listing.

    Args:
        user_id: Okta user ID.

    Returns:
        A user row dict satisfying the User model validation.
    """
    return {
        "id": user_id,
        "created": "2026-01-01T00:00:00Z",
        "status": "ACTIVE",
        "profile": {"login": f"{user_id}@example.com"},
    }


class PipelineStubPool:
    """ClientPool stand-in for full pipeline runs of the factor streams.

    Attributes:
        paths: Every paginated path, in call order, for request-count asserts.
        _users: Rows served for the users listing.
        _assignees: Rows served for the privileged assignee inventory listing.
        _groups: Rows served for the expanded groups listing.
        _members_by_group: Member rows served per group ID.
        _factors_by_user: Factor rows served per user ID.
    """

    def __init__(
        self,
        users: list[dict[str, object]],
        assignees: list[dict[str, object]],
        groups: list[dict[str, object]],
        members_by_group: dict[str, list[dict[str, object]]],
        factors_by_user: dict[str, list[dict[str, object]]],
    ) -> None:
        self.paths: list[str] = []
        self._users = users
        self._assignees = assignees
        self._groups = groups
        self._members_by_group = members_by_group
        self._factors_by_user = factors_by_user

    def paginate(self, path: str, **kwargs: object) -> list[list[dict[str, object]]]:
        """Return the canned single page matching the requested path.

        Args:
            path: Okta API path (users, assignees, groups, members, factors).
            **kwargs: Ignored pagination options accepted for compatibility.

        Returns:
            A one-page list of rows for the addressed listing.
        """
        self.paths.append(path)
        if path == "/api/v1/users":
            return [self._users]
        if path == "/api/v1/iam/assignees/users":
            return [self._assignees]
        if path.startswith("/api/v1/groups?"):
            return [self._groups]
        if path.endswith("/factors"):
            return [self._factors_by_user.get(path.split("/")[-2], [])]
        return [self._members_by_group.get(path.split("/")[-2], [])]


def test_factor_pipeline_loads_one_deduplicated_replaced_snapshot(tmp_path) -> None:
    """Both replace writers merge into one deduped user_factors snapshot.

    Runs the real transformers through a dlt pipeline into DuckDB, twice:
    the first run asserts rows from both streams land in one table with a
    multi-path super admin fetched exactly once, and that the preprocessing
    transform materializes the NULL/0/N counts; the second run asserts the
    snapshot is replaced rather than appended to.

    Args:
        tmp_path: Pytest fixture providing an isolated working directory.
    """
    import dlt
    import duckdb

    from openhound_okta.lookup import OktaLookup
    from openhound_okta.source import (
        admin_group_member_factors,
        group_memberships,
        groups,
        privileged_users,
        user_factors,
        users,
    )

    db_path = str(tmp_path / "collected.duckdb")

    def run_collection(
        assignees: list[dict[str, object]],
        factors_by_user: dict[str, list[dict[str, object]]],
    ) -> PipelineStubPool:
        """Run one full collection of the factor-related resources.

        Args:
            assignees: Privileged assignee rows for this run.
            factors_by_user: Factor rows per user for this run.

        Returns:
            The stub pool, for request-count assertions.
        """
        pool = PipelineStubPool(
            users=[make_okta_user(f"user-{i}") for i in range(1, 6)],
            assignees=assignees,
            groups=[
                make_group_item("admin-group", admin=True, users_count=2),
                make_group_item("plain-group", admin=False, users_count=1),
            ],
            members_by_group={
                "admin-group": [make_member("user-1"), make_member("user-3")],
                "plain-group": [make_member("user-4")],
            },
            factors_by_user=factors_by_user,
        )
        ctx = SourceContext(
            pool=cast(ClientPool, pool), tenant_domain="example.okta.com"
        )
        claims = UserFactorClaims()
        memberships_resource = groups(ctx) | group_memberships(ctx)
        pipeline = dlt.pipeline(
            pipeline_name="factor_snapshot_test",
            pipelines_dir=str(tmp_path / "dlt"),
            destination=dlt.destinations.duckdb(db_path),
            dataset_name="okta",
        )
        pipeline.run(
            [
                users(ctx),
                privileged_users(ctx) | user_factors(ctx, claims),
                memberships_resource | admin_group_member_factors(ctx, claims),
            ]
        )
        return pool

    def factor_table() -> dict[str, list[str | None]]:
        """Read the loaded user_factors snapshot grouped by user ID.

        Returns:
            Mapping of user ID to its sorted factor IDs (None = scope marker).
        """
        con = duckdb.connect(db_path)
        rows = con.execute(
            "SELECT user_id, id FROM okta.user_factors ORDER BY user_id, id"
        ).fetchall()
        con.close()
        table: dict[str, list[str | None]] = {}
        for user_id, factor_id in rows:
            table.setdefault(user_id, []).append(factor_id)
        return table

    # user-1 is a multi-path super admin: direct assignee AND admin-group
    # member. user-2 is direct only (with an unusable pending factor),
    # user-3 admin-group only (no factors), user-4 is only in a non-admin
    # group, user-5 is unprivileged.
    pool = run_collection(
        assignees=[{"id": "user-1"}, {"id": "user-2"}],
        factors_by_user={
            "user-1": [
                {"id": "factor-1", "status": "ACTIVE"},
                {"id": "factor-2", "status": "ACTIVE"},
            ],
            "user-2": [{"id": "factor-3", "status": "PENDING_ACTIVATION"}],
        },
    )

    assert pool.paths.count("/api/v1/users/user-1/factors") == 1
    assert factor_table() == {
        "user-1": ["factor-1", "factor-2"],
        "user-2": ["factor-3"],
        "user-3": [None],  # scope marker: covered, no enrolled factors
    }

    con = duckdb.connect(db_path)
    # Convert rehydrates models from the collected JSONL, so the counts must
    # be reachable through the lookup, which is what as_node consults.
    lookup = OktaLookup(con)
    counts = {
        user_id: lookup.user_authentication_factors_count(user_id)
        for user_id in ("user-1", "user-2", "user-3", "user-4", "user-5")
    }
    con.close()
    assert counts == {
        "user-1": 2,
        # Collected, but the only factor is pending activation: no usable MFA.
        "user-2": 0,
        "user-3": 0,
        "user-4": None,
        "user-5": None,
    }

    # A second collection covers only user-1 with a single factor: the
    # replace disposition must rebuild the snapshot, not append to it.
    run_collection(
        assignees=[{"id": "user-1"}],
        factors_by_user={"user-1": [{"id": "factor-9", "status": "ACTIVE"}]},
    )

    assert factor_table() == {"user-1": ["factor-9"], "user-3": [None]}
