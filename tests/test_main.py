import pytest

from openhound_okta import main
from openhound_okta.saml_eligibility import configured_saml_eligibility_preflight


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            {
                "sources.okta.credentials.base_url": "https://preview2.example",
                "sources.source.okta.credentials.base_url": "https://legacy.example",
            },
            "preview2.example",
        ),
        (
            {"sources.source.okta.credentials.base_url": "https://legacy.example"},
            "legacy.example",
        ),
    ],
)
def test_tenant_domain_supports_canonical_and_legacy_config(
    monkeypatch, values, expected
):
    monkeypatch.setattr(main.dlt.secrets, "get", values.get)

    assert main._tenant_domain_from_config() == expected


def test_tenant_domain_rejects_missing_config(monkeypatch):
    monkeypatch.setattr(main.dlt.secrets, "get", lambda _key: None)

    with pytest.raises(ValueError, match="base URL is unavailable"):
        main._tenant_domain_from_config()


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            {
                "sources.okta.saml_group_eligibility_mode": "shadow",
                "sources.source.okta.saml_group_eligibility_mode": "expanded",
            },
            "shadow",
        ),
        (
            {"sources.source.okta.saml_group_eligibility_mode": "shadow"},
            "shadow",
        ),
        ({}, "expanded"),
    ],
)
def test_saml_group_eligibility_mode_supports_canonical_and_legacy_config(
    monkeypatch, values, expected
):
    monkeypatch.setattr(main.dlt.config, "get", values.get)

    assert main._saml_group_eligibility_mode_from_config() == expected


def test_saml_group_eligibility_mode_rejects_unknown_config(monkeypatch):
    monkeypatch.setattr(
        main.dlt.config,
        "get",
        {"sources.okta.saml_group_eligibility_mode": "authoritative"}.get,
    )

    with pytest.raises(ValueError, match="expanded or shadow"):
        main._saml_group_eligibility_mode_from_config()


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"sources.okta.saml_eligibility_preflight": True}, True),
        ({"sources.okta.saml_eligibility_preflight": "true"}, True),
        ({"sources.okta.saml_eligibility_preflight": "false"}, False),
        ({"sources.source.okta.saml_eligibility_preflight": True}, True),
        ({}, False),
    ],
)
def test_saml_eligibility_preflight_supports_canonical_and_legacy_config(
    values, expected
):
    assert configured_saml_eligibility_preflight(values.get) is expected


@pytest.mark.parametrize("value", ("TRUE", "1", 1))
def test_saml_eligibility_preflight_rejects_non_boolean_values(value):
    with pytest.raises(ValueError, match="true or false"):
        configured_saml_eligibility_preflight(
            {"sources.okta.saml_eligibility_preflight": value}.get
        )
