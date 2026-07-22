import pytest

from openhound_okta import main


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
