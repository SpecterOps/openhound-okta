import inspect
from types import SimpleNamespace

import dlt
import pytest
from dlt.extract.items_transform import FilterItem

from openhound_okta.app_names import AppName
from openhound_okta.models.application_users import ALWAYS_COLLECTED_APP_USERS
from openhound_okta.models.hybrid_auth import SUPPORTED_HYBRID_AUTH_APPS
from openhound_okta.oin_routes.registry import OIN_ROUTE_REGISTRY
from openhound_okta.source import (
    APPLICATION_USERS_PAGE_SIZE,
    app_user_collection_filter,
    application_users,
    source,
)
from openhound_okta.utils.auth import OktaTokenCredentials


def _application(app_id: str, name: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=app_id,
        features=[],
        name=name,
        label=name,
        status="ACTIVE",
        settings=None,
        credentials=None,
        sign_on_mode="SAML_2_0",
    )


class RecordingPool:
    def __init__(self):
        self.paths: list[str] = []

    def paginate(self, path, **kwargs):
        self.paths.append(path)
        yield [
            {
                "id": "00u1",
                "created": "2024-01-01T00:00:00.000Z",
                "status": "ACTIVE",
                "scope": "USER",
                "profile": {},
            }
        ]


def test_always_collected_app_users_cover_hybrid_and_oin_route_apps():
    assert SUPPORTED_HYBRID_AUTH_APPS <= ALWAYS_COLLECTED_APP_USERS
    assert {"active_directory", "ldap_interface"} <= ALWAYS_COLLECTED_APP_USERS
    assert set(OIN_ROUTE_REGISTRY) <= ALWAYS_COLLECTED_APP_USERS


@pytest.mark.parametrize(
    ("name", "app_id", "app_ids", "expected"),
    [
        ("active_directory", "0oa_ad", frozenset(), True),
        ("slack", "0oa_slack", frozenset(), True),
        (AppName.ZOOM, "0oa_zoom", frozenset(), True),
        ("custom_saml", "0oa_listed", frozenset({"0oa_listed"}), True),
        ("custom_saml", "0oa_custom", frozenset({"0oa_listed"}), False),
        ("custom_saml", "0oa_custom", frozenset(), False),
    ],
)
def test_app_user_collection_filter(name, app_id, app_ids, expected):
    keep = app_user_collection_filter(app_ids)

    assert keep(_application(app_id, name)) is expected


@pytest.mark.parametrize(
    ("limited", "expected_paths"),
    [
        (
            False,
            [
                "/api/v1/apps/0oa_ad/users",
                "/api/v1/apps/0oa_custom/users",
                "/api/v1/apps/0oa_listed/users",
            ],
        ),
        (True, ["/api/v1/apps/0oa_ad/users", "/api/v1/apps/0oa_listed/users"]),
    ],
)
def test_filter_skips_application_user_requests_for_unlisted_apps(
    limited, expected_paths
):
    pool = RecordingPool()
    ctx = SimpleNamespace(
        pool=pool,
        application_users_page_size=APPLICATION_USERS_PAGE_SIZE,
    )

    @dlt.resource(name="applications")
    def fake_applications():
        yield _application("0oa_ad", "active_directory")
        yield _application("0oa_custom", "custom_saml")
        yield _application("0oa_listed", "custom_saml")

    resource = fake_applications() | application_users(ctx)
    if limited:
        resource.add_filter(
            app_user_collection_filter(frozenset({"0oa_listed"})), insert_at=0
        )

    rows = list(resource)

    assert sorted(pool.paths) == expected_paths
    assert sorted(row["app_id"] for row in rows) == [
        path.split("/")[4] for path in expected_paths
    ]


def _application_users_resource(**kwargs):
    credentials = OktaTokenCredentials(
        base_url="https://example.okta.test",
        token="token",
    )
    resources = inspect.unwrap(source)(credentials=credentials, **kwargs)
    return next(
        resource for resource in resources if resource.name == "application_users"
    )


def test_source_adds_filter_only_when_collection_is_limited():
    unlimited = _application_users_resource()
    limited = _application_users_resource(
        limit_app_user_collection=True,
        app_user_collection_app_ids=["0oa_listed"],
    )

    assert not isinstance(unlimited._pipe.steps[0], FilterItem)
    assert isinstance(limited._pipe.steps[0], FilterItem)
    assert limited._pipe.steps[0](_application("0oa_listed", "custom_saml")) is not None
    assert limited._pipe.steps[0](_application("0oa_custom", "custom_saml")) is None
