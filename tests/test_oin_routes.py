from dataclasses import fields, replace

import pytest

from openhound_okta.oin_routes import OinRouteResolution
from openhound_okta.oin_routes.declarative import (
    RouteProfile,
    RouteTemplate,
    RouteVariable,
)
from openhound_okta.oin_routes.registry import (
    OIN_ROUTE_PROVIDERS,
    OIN_ROUTE_REGISTRY,
    build_registry,
    resolve_oin_routes,
)
from openhound_okta.oin_routes.settings_contract import (
    COLLECTION_TIME_ONLY_RESOLVER_APP_FIELDS,
    SAML_ROUTE_APP_SETTING_PROPERTIES,
    canonical_app_setting_property_name,
)
from openhound_okta.oin_routes.validators import (
    host_label,
    https_url,
    present_string,
    slack_domain,
)


def _multi_route_profile(*app_keys: str) -> RouteProfile:
    return RouteProfile(
        profile_id="test_multi_route",
        app_keys=app_keys,
        variables=(
            RouteVariable(
                name="tenant",
                app_field="tenant",
                validator=present_string,
                diagnostic="missing_settings.app.tenant",
            ),
        ),
        routes=(
            RouteTemplate(
                acs="https://{tenant}.example.test/saml/primary",
                sp_entity="https://{tenant}.example.test/saml",
                acs_variables=("tenant",),
                sp_entity_variables=("tenant",),
                index=0,
            ),
            RouteTemplate(
                acs="https://{tenant}.example.test/saml/secondary",
                sp_entity="https://{tenant}.example.test/saml",
                acs_variables=("tenant",),
                sp_entity_variables=("tenant",),
                index=1,
                is_default=False,
            ),
        ),
        target_product_family="test_product",
        route_source="settings.app+test_route",
        extraction_mode="allowlisted_deterministic_route",
        evidence_references=("test:evidence",),
        evidence_reviewed_at="2026-08-13",
    )


def test_declarative_profile_preserves_multiple_route_tuples():
    resolution = _multi_route_profile("test_app").resolve({"tenant": "acme"})

    assert [route.acs_url for route in resolution.routes] == [
        "https://acme.example.test/saml/primary",
        "https://acme.example.test/saml/secondary",
    ]
    assert [route.index for route in resolution.routes] == [0, 1]
    assert resolution.diagnostics == ()


def test_declarative_profile_fails_closed_when_a_variable_is_missing():
    resolution = _multi_route_profile("test_app").resolve({})

    assert resolution.routes == ()
    assert resolution.diagnostics == ("missing_settings.app.tenant",)


def test_registry_rejects_duplicate_app_keys():
    with pytest.raises(ValueError, match="duplicate OIN route app key: test_app"):
        build_registry(
            (
                _multi_route_profile("test_app"),
                replace(
                    _multi_route_profile("test_app"),
                    profile_id="other_test_profile",
                ),
            )
        )


def test_registry_rejects_duplicate_profile_ids():
    with pytest.raises(
        ValueError,
        match="duplicate OIN route profile ID: test_multi_route",
    ):
        build_registry(
            (
                _multi_route_profile("test_app_one"),
                _multi_route_profile("test_app_two"),
            )
        )


def test_declarative_profile_requires_route_source_provenance():
    with pytest.raises(ValueError, match="must use either instance variables"):
        RouteProfile(
            profile_id="test_static_route",
            app_keys=("test_app",),
            variables=(),
            routes=(
                RouteTemplate(
                    acs="https://example.test/saml/acs",
                    sp_entity="https://example.test/saml",
                    acs_variables=(),
                    sp_entity_variables=(),
                ),
            ),
            target_product_family="test_product",
            route_source="documented_route",
            extraction_mode="allowlisted_deterministic_route",
            evidence_references=("test:evidence",),
            evidence_reviewed_at="2026-08-13",
        )


def test_declarative_profile_supports_documented_static_route_values():
    profile = RouteProfile(
        profile_id="test_static_entity",
        app_keys=("test_app",),
        variables=(
            RouteVariable(
                name="tenant",
                app_field="tenant",
                validator=present_string,
                diagnostic="missing_settings.app.tenant",
            ),
        ),
        routes=(
            RouteTemplate(
                acs="https://{tenant}.example.test/saml/acs",
                sp_entity="https://example.test/saml",
                acs_variables=("tenant",),
                sp_entity_variables=(),
                sp_entity_static_source="documented_static_sp_entity",
            ),
        ),
        target_product_family="test_product",
        route_source="settings.app+documented_route",
        extraction_mode="allowlisted_deterministic_route",
        evidence_references=("test:evidence",),
        evidence_reviewed_at="2026-08-13",
    )

    route = profile.resolve({"tenant": "acme"}).routes[0]

    assert route.sp_entity_id == "https://example.test/saml"
    assert route.sp_entity_source_field == "documented_static_sp_entity"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("workspace", "workspace"),
        ("workspace-name", "workspace-name"),
        ("workspace.enterprise", "workspace.enterprise"),
        ("workspace.slack.com", None),
        ("workspace.other", None),
        (" workspace", None),
        ("workspace\x00", None),
        ("", None),
        (None, None),
    ],
)
def test_slack_domain_validator(value, expected):
    assert slack_domain(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("company", "company"),
        ("company-name", "company-name"),
        ("company.zoom.us", None),
        (" company", None),
        ("", None),
        (None, None),
    ],
)
def test_host_label_validator(value, expected):
    assert host_label(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://miro.com/sso/saml", "https://miro.com/sso/saml"),
        ("https://miro.com/", "https://miro.com/"),
        ("http://miro.com/sso/saml", None),
        ("https://user@miro.com/sso/saml", None),
        ("https://miro.com/sso/saml?tenant=one", None),
        (" https://miro.com/sso/saml", None),
        ("https://miro.com/sso/\x00saml", None),
    ],
)
def test_https_url_validator(value, expected):
    assert https_url(value) == expected


def test_miro_provider_uses_documented_default_route_when_overrides_are_explicitly_null():
    resolution = resolve_oin_routes(
        "realtime_board",
        {"customAcsUrl": None, "customEntityId": None},
    )

    assert resolution.diagnostics == ()
    assert len(resolution.routes) == 1
    route = resolution.routes[0]
    assert route.acs_url == "https://miro.com/sso/saml"
    assert route.sp_entity_id == "https://miro.com/"
    assert route.route_source == "documented_miro_default_route"
    assert route.extraction_mode == "allowlisted_static_default_route"
    assert route.acs_source_field == "documented_static_miro_acs"
    assert route.sp_entity_source_field == "documented_static_miro_sp_entity"


def test_asana_provider_uses_observed_default_route():
    resolution = resolve_oin_routes("asana", {})

    assert resolution.diagnostics == ()
    assert len(resolution.routes) == 1
    route = resolution.routes[0]
    assert route.acs_url == "https://app.asana.com/-/saml/consume"
    assert route.sp_entity_id == "https://app.asana.com"
    assert route.route_source == "documented_asana_default_route"
    assert route.extraction_mode == "allowlisted_static_default_route"
    assert route.acs_source_field == "documented_static_asana_acs"
    assert route.sp_entity_source_field == "observed_static_asana_audience"


def test_miro_provider_preserves_complete_miro_custom_route():
    resolution = resolve_oin_routes(
        "realtime_board",
        {
            "customAcsUrl": "https://workspace.miro.com/sso/saml/12345",
            "customEntityId": "https://workspace.miro.com/12345",
        },
    )

    assert resolution.diagnostics == ()
    route = resolution.routes[0]
    assert route.acs_url == "https://workspace.miro.com/sso/saml/12345"
    assert route.sp_entity_id == "https://workspace.miro.com/12345"
    assert route.route_source == "settings.app"
    assert route.extraction_mode == "oin_explicit_fields"
    assert route.acs_source_field == "settings.app.customAcsUrl"
    assert route.sp_entity_source_field == "settings.app.customEntityId"


@pytest.mark.parametrize(
    ("app_settings", "expected_diagnostics"),
    [
        (
            {},
            (
                "missing_or_malformed_settings.app.customAcsUrl",
                "missing_or_malformed_settings.app.customEntityId",
            ),
        ),
        (
            {"customAcsUrl": None},
            (
                "missing_or_malformed_settings.app.customAcsUrl",
                "missing_or_malformed_settings.app.customEntityId",
            ),
        ),
        (
            {"customEntityId": None},
            (
                "missing_or_malformed_settings.app.customAcsUrl",
                "missing_or_malformed_settings.app.customEntityId",
            ),
        ),
        (
            {"customAcsUrl": "https://miro.com/sso/saml"},
            ("missing_or_malformed_settings.app.customEntityId",),
        ),
        (
            {"customAcsUrl": None, "customEntityId": "https://miro.com/"},
            ("missing_or_malformed_settings.app.customAcsUrl",),
        ),
        (
            {"customAcsUrl": "", "customEntityId": ""},
            (
                "missing_or_malformed_settings.app.customAcsUrl",
                "missing_or_malformed_settings.app.customEntityId",
            ),
        ),
        (
            {
                "customAcsUrl": "https://miro.example.test/sso/saml",
                "customEntityId": "https://miro.example.test/",
            },
            (
                "missing_or_malformed_settings.app.customAcsUrl",
                "missing_or_malformed_settings.app.customEntityId",
            ),
        ),
    ],
)
def test_miro_provider_fails_closed_for_incomplete_or_malformed_custom_route(
    app_settings, expected_diagnostics
):
    resolution = resolve_oin_routes("realtime_board", app_settings)

    assert resolution.routes == ()
    assert resolution.diagnostics == expected_diagnostics


def test_bundled_providers_have_evidence_metadata_and_unique_keys():
    registered_keys = [
        app_key for provider in OIN_ROUTE_PROVIDERS for app_key in provider.app_keys
    ]

    assert len(registered_keys) == len(set(registered_keys))
    assert set(registered_keys) == set(OIN_ROUTE_REGISTRY)
    assert all(provider.evidence_references for provider in OIN_ROUTE_PROVIDERS)
    assert all(provider.evidence_reviewed_at for provider in OIN_ROUTE_PROVIDERS)


def test_bundled_resolver_app_fields_are_graph_expressed_or_documented():
    from openhound_okta.models.application import (
        APP_SETTING_PROPERTY_NAMES,
        ApplicationProperties,
    )

    resolver_fields = {
        app_field
        for provider in OIN_ROUTE_PROVIDERS
        for app_field in provider.app_fields
    }
    graph_property_names = {field.name for field in fields(ApplicationProperties)}

    assert set(COLLECTION_TIME_ONLY_RESOLVER_APP_FIELDS) <= resolver_fields
    assert all(
        reason.strip() for reason in COLLECTION_TIME_ONLY_RESOLVER_APP_FIELDS.values()
    )
    for app_field in resolver_fields:
        if app_field in COLLECTION_TIME_ONLY_RESOLVER_APP_FIELDS:
            continue
        property_name = canonical_app_setting_property_name(app_field)
        assert property_name in SAML_ROUTE_APP_SETTING_PROPERTIES
        assert property_name in APP_SETTING_PROPERTY_NAMES
        assert property_name in graph_property_names


def test_unknown_app_has_no_oin_route_evidence():
    assert resolve_oin_routes("unknown_app", {}) == OinRouteResolution()
