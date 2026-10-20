import logging

import pytest
import requests

from openhound_okta.utils.entra_tenant import EntraTenantIdResolver


def _openid_configuration_get(requested, tenant_id="tenant-id"):
    def get(url, **kwargs):
        requested.append((url, kwargs))
        response = requests.Response()
        response.status_code = 200
        response._content = (
            b'{"token_endpoint":"https://login.microsoftonline.com/'
            + tenant_id.encode()
            + b'/oauth2/v2.0/token"}'
        )
        return response

    return get


def _office365_application(msft_tenant):
    return {
        "name": "office365",
        "signOnMode": "SAML_1_1",
        "settings": {"app": {"msftTenant": msft_tenant}},
    }


def test_entra_tenant_id_is_derived_from_openid_configuration():
    requested = []
    resolver = EntraTenantIdResolver(
        get=_openid_configuration_get(
            requested, tenant_id="31537af4-6d77-4bb9-a681-d2394888ea26"
        )
    )

    tenant_id = resolver.resolve("contoso.onmicrosoft.com")

    assert tenant_id == "31537af4-6d77-4bb9-a681-d2394888ea26"
    assert requested == [
        (
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/"
            ".well-known/openid-configuration",
            {},
        )
    ]


@pytest.mark.parametrize(
    ("msft_tenant", "expected_domain"),
    [
        ("contoso", "contoso.onmicrosoft.com"),
        ("contoso.onmicrosoft.com", "contoso.onmicrosoft.com"),
        ("Contoso", "contoso.onmicrosoft.com"),
        ("Contoso.OnMicrosoft.com", "contoso.onmicrosoft.com"),
        ("  contoso ", "contoso.onmicrosoft.com"),
        ("contoso.com", "contoso.com"),
        (
            "31537AF4-6D77-4BB9-A681-D2394888EA26",
            "31537af4-6d77-4bb9-a681-d2394888ea26",
        ),
    ],
)
def test_msft_tenant_setting_is_normalized_without_doubling_the_suffix(
    msft_tenant, expected_domain
):
    requested = []

    EntraTenantIdResolver(get=_openid_configuration_get(requested)).resolve(msft_tenant)

    assert [url for url, _ in requested] == [
        f"https://login.microsoftonline.com/{expected_domain}/"
        ".well-known/openid-configuration"
    ]


def test_office365_saml_app_is_enriched_with_entra_tenant_id():
    resolver = EntraTenantIdResolver(get=_openid_configuration_get([]))

    enriched = resolver.enrich(_office365_application("contoso"))

    assert enriched["settings"]["app"] == {
        "msftTenant": "contoso",
        "microsoftTenantId": "tenant-id",
    }


def test_entra_tenant_id_is_resolved_once_per_tenant():
    requested = []
    resolver = EntraTenantIdResolver(get=_openid_configuration_get(requested))

    enriched = [
        resolver.enrich(_office365_application(msft_tenant))
        for msft_tenant in ("contoso", "Contoso", "contoso.onmicrosoft.com")
    ]

    assert [app["settings"]["app"]["microsoftTenantId"] for app in enriched] == [
        "tenant-id"
    ] * 3
    assert [url for url, _ in requested] == [
        "https://login.microsoftonline.com/contoso.onmicrosoft.com/"
        ".well-known/openid-configuration"
    ]


def test_unresolvable_entra_tenant_is_looked_up_once(caplog):
    requested = []

    def get(url, **kwargs):
        requested.append(url)
        raise requests.ConnectionError("login.microsoftonline.com unreachable")

    resolver = EntraTenantIdResolver(get=get)

    with caplog.at_level(logging.WARNING, logger="openhound_okta.utils.entra_tenant"):
        enriched = [
            resolver.enrich(_office365_application("contoso")) for _ in range(2)
        ]

    assert [app["settings"]["app"] for app in enriched] == [
        {"msftTenant": "contoso"}
    ] * 2
    assert len(requested) == 1
    assert [record.getMessage() for record in caplog.records] == [
        "Unable to resolve Microsoft tenant ID for contoso.onmicrosoft.com"
    ]


@pytest.mark.parametrize(
    ("url", "expected_tenant_id"),
    [
        (
            "https://login.microsoftonline.com/31537af4-6d77-4bb9-a681-d2394888ea26"
            "/oauth2/v2.0/token",
            "31537af4-6d77-4bb9-a681-d2394888ea26",
        ),
        ("https://login.microsoftonline.com/tenant-1/saml2", "tenant-1"),
        ("https://login.microsoftonline.com/saml2", None),
        ("https://login.microsoftonline.com/", None),
        ("https://example.okta.test/tenant-1/saml2", None),
    ],
)
def test_tenant_id_is_taken_from_tenant_scoped_microsoft_urls(url, expected_tenant_id):
    assert EntraTenantIdResolver.tenant_id_from_url(url) == expected_tenant_id
