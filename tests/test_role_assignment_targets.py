from unittest.mock import MagicMock

import pytest
from requests import HTTPError, Response

from openhound_okta.source import (
    _fetch_role_assignment_targets,
    _merge_role_targets,
)


def _make_http_error(status_code: int) -> HTTPError:
    response = Response()
    response.status_code = status_code
    return HTTPError(response=response)


def _fake_pool(responses: dict[str, object]) -> MagicMock:
    """Build a ClientPool-like mock whose ``paginate`` returns lists or raises."""

    def paginate(path: str):
        result = responses[path]
        if isinstance(result, Exception):
            raise result
        return iter(result)

    pool = MagicMock()
    pool.paginate.side_effect = paginate
    return pool


def test_fetch_targets_returns_groups_and_apps():
    base = "/api/v1/users/u1/roles/r1"
    pool = _fake_pool(
        {
            f"{base}/targets/groups": [[{"id": "g1", "type": "OKTA_GROUP",
                                          "objectClass": ["okta:group"]}]],
            f"{base}/targets/catalog/apps": [
                [{"name": "okta_org2org", "displayName": "Test App",
                  "status": "ACTIVE", "category": "OTHER", "id": "a1"}]
            ],
        }
    )

    targets = _fetch_role_assignment_targets(pool, base)

    assert targets["groups"][0]["id"] == "g1"
    assert targets["catalog"]["apps"][0]["id"] == "a1"


def test_fetch_targets_skips_400_and_does_not_raise():
    base = "/api/v1/users/u1/roles/r1"
    pool = _fake_pool(
        {
            f"{base}/targets/groups": _make_http_error(400),
            f"{base}/targets/catalog/apps": _make_http_error(400),
        }
    )

    assert _fetch_role_assignment_targets(pool, base) == {}


def test_fetch_targets_propagates_non_400_errors():
    base = "/api/v1/users/u1/roles/r1"
    pool = _fake_pool(
        {
            f"{base}/targets/groups": _make_http_error(500),
            f"{base}/targets/catalog/apps": [],
        }
    )

    with pytest.raises(HTTPError):
        _fetch_role_assignment_targets(pool, base)


def test_fetch_targets_omits_empty_keys():
    base = "/api/v1/users/u1/roles/r1"
    pool = _fake_pool(
        {
            f"{base}/targets/groups": [[]],
            f"{base}/targets/catalog/apps": [[]],
        }
    )

    assert _fetch_role_assignment_targets(pool, base) == {}


def test_merge_role_targets_preserves_existing_embedded():
    role = {"id": "r1", "type": "APP_ADMIN", "_embedded": {"other": 1}}
    merged = _merge_role_targets(role, {"groups": [{"id": "g1"}]})
    assert merged["_embedded"]["other"] == 1
    assert merged["_embedded"]["targets"]["groups"][0]["id"] == "g1"


def test_merge_role_targets_noop_when_empty():
    role = {"id": "r1", "type": "APP_ADMIN"}
    assert _merge_role_targets(role, {}) is role
    assert "_embedded" not in role


def test_user_role_list_url_has_no_expand_parameters():
    """Regression: the list URL must not include any ``expand`` query parameter.

    Triggered the Okta 400 in production when two ``expand`` values were sent.
    """
    import inspect

    from openhound_okta import source

    src_text = inspect.getsource(source)
    assert "expand=targets" not in src_text
