from dataclasses import asdict

import pytest
from openhound.sources.opengraph.entries import GraphContent

from openhound_okta.kinds import edges as ek
from openhound_okta.models import ApplicationUser


def make_application_user(
    *,
    app_name: str,
    scope: str,
    app_features: list[str] | None = None,
    profile: dict | None = None,
    sync_state: str = "SYNCHRONIZED",
    external_id: str | None = None,
):
    return ApplicationUser.model_validate(
        {
            "id": "user-1",
            "created": "2026-01-01T00:00:00Z",
            "profile": profile or {},
            "status": "ACTIVE",
            "app_id": "app-1",
            "app_name": app_name,
            "app_label": "Example App",
            "app_features": app_features or [],
            "scope": scope,
            "syncState": sync_state,
            "externalId": external_id,
        }
    )


def sync_edges(app_user):
    return [
        edge
        for edge in app_user.edges
        if edge.kind in {ek.USER_PUSH, ek.USER_PULL}
    ]


@pytest.mark.parametrize(
    ("app_name", "scope", "app_features", "profile", "expected_kind"),
    [
        ("active_directory", "USER", [], {}, ek.USER_PULL),
        ("active_directory", "GROUP", [], {}, ek.USER_PUSH),
        ("ldap_interface", "GROUP", [], {}, ek.USER_PULL),
        ("githubcloud", "GROUP", [], {}, ek.USER_PUSH),
        ("githubcloud", "USER", ["PROFILE_MASTERING"], {}, ek.USER_PULL),
        ("githubcloud", "USER", [], {}, ek.USER_PUSH),
        ("okta_org2org", "USER", ["PROFILE_MASTERING"], {}, ek.USER_PULL),
        (
            "okta_org2org",
            "USER",
            ["PROFILE_MASTERING"],
            {"initialStatus": "ACTIVE"},
            ek.USER_PUSH,
        ),
    ],
)
def test_user_sync_direction_matches_oktahound_heuristics(
    app_name, scope, app_features, profile, expected_kind
):
    app_user = make_application_user(
        app_name=app_name,
        scope=scope,
        app_features=app_features,
        profile=profile,
    )

    edges = sync_edges(app_user)

    assert len(edges) == 1
    assert edges[0].kind == expected_kind


@pytest.mark.parametrize(
    ("app_name", "scope"),
    [
        ("okta_flow_sso", "USER"),
        ("okta_flow_sso", "GROUP"),
        ("okta_atspoke_sso", "USER"),
        ("okta_atspoke_sso", "GROUP"),
    ],
)
def test_outbound_sync_edges_are_suppressed_for_ignored_builtin_apps(
    app_name, scope
):
    app_user = make_application_user(app_name=app_name, scope=scope)

    assert sync_edges(app_user) == []


def test_unsynchronized_app_users_do_not_emit_user_push_or_pull_edges():
    app_user = make_application_user(
        app_name="githubcloud",
        scope="GROUP",
        sync_state="DISABLED",
    )

    assert sync_edges(app_user) == []


@pytest.mark.parametrize(
    ("app_features", "profile"),
    [
        (["PROFILE_MASTERING"], {}),
        (["PUSH_PASSWORD_UPDATES"], {"initialStatus": "ACTIVE"}),
    ],
)
def test_org2org_missing_external_id_skips_direct_sync_edges(
    app_features, profile
):
    app_user = make_application_user(
        app_name="okta_org2org",
        scope="USER",
        app_features=app_features,
        profile=profile,
    )

    direct_sync_edges = [
        edge
        for edge in app_user.edges
        if edge.kind in {ek.USER_SYNC, ek.PASSWORD_SYNC}
    ]

    assert direct_sync_edges == []

    payload = {
        "graph": {
            "entity_type": "edge",
            "content": [asdict(edge) for edge in app_user.edges],
        }
    }
    GraphContent.model_validate(payload)
