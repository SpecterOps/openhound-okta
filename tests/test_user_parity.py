import duckdb

from openhound_okta.lookup import OktaLookup
from openhound_okta.models import User
from openhound_okta.source import user_factors


class StubLookup:
    def __init__(
        self,
        *,
        has_role_assignments: bool = False,
        authentication_factors: int = 0,
    ):
        self._has_role_assignments = has_role_assignments
        self._authentication_factors = authentication_factors

    def org_id(self):
        return "org-1"

    def has_role_assignments(self, principal_id, principal_type):
        assert principal_id == "user-1"
        assert principal_type == "user"
        return self._has_role_assignments

    def user_authentication_factors_count(self, user_id):
        assert user_id == "user-1"
        return self._authentication_factors


def make_user(
    *,
    has_role_assignments: bool = False,
    authentication_factors: int = 0,
    **overrides,
):
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
        authentication_factors=authentication_factors,
    )
    user._extras = {"tenant": "example.okta.com"}
    return user


def test_user_node_emits_core_oktahound_equivalent_properties():
    user = make_user(has_role_assignments=True, authentication_factors=3)

    properties = user.as_node.properties

    assert properties.name == "ALICE@EXAMPLE.COM"
    assert properties.displayname == "Alice Example"
    assert properties.okta_domain == "example.okta.com"
    assert properties.has_role_assignments is True
    assert properties.authentication_factors == 3
    assert properties.enabled is True


def test_user_node_falls_back_to_login_when_display_name_is_missing():
    user = make_user(profile={"login": "alice@example.com"})

    assert user.as_node.properties.displayname == "alice@example.com"


def test_user_lookup_counts_factors_and_defaults_to_zero_without_table(caplog):
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.user_factors (user_id VARCHAR)")
    con.execute(
        "INSERT INTO okta.user_factors VALUES "
        "('user-1'), ('user-1'), ('user-1'), ('user-2')"
    )

    lookup = OktaLookup(con)

    assert lookup.user_authentication_factors_count("user-1") == 3

    empty_lookup = OktaLookup(duckdb.connect())
    assert empty_lookup.user_authentication_factors_count("user-1") == 0
    assert "DuckDB lookup failed, missing table" not in caplog.text


def test_user_factor_collection_is_opt_in():
    assert user_factors(None).selected is False
