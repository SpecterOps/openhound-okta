from openhound_okta.models import ClientApplication


def test_client_application_parses_live_clients_payload():
    # Shape of a GET /oauth2/v1/clients item as returned by Okta for an
    # Okta-managed browser client.
    client = ClientApplication.model_validate(
        {
            "client_id": "okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26",
            "client_id_issued_at": 1759396892,
            "client_name": "Okta Dashboard",
            "client_uri": None,
            "logo_uri": None,
            "redirect_uris": ["https://example.okta.com/enduser/callback"],
            "post_logout_redirect_uris": ["https://example.okta.com/login/signout"],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "initiate_login_uri": "https://example.okta.com/app/UserHome",
            "token_endpoint_auth_method": "none",
            "application_type": "browser",
            "software_id": "4796a70a-ef61-5a63-99eb-0d3f2633d61b",
        }
    )

    assert client.client_name == "Okta Dashboard"
    assert client.client_uri is None
    assert client.logo_uri is None
    assert client.redirect_uris == ["https://example.okta.com/enduser/callback"]
    assert client.post_logout_redirect_uris == [
        "https://example.okta.com/login/signout"
    ]
    assert client.initiate_login_uri == "https://example.okta.com/app/UserHome"
    assert client.client_secret_expires_at is None
    assert client.jwks is None
    assert client.software_id == "4796a70a-ef61-5a63-99eb-0d3f2633d61b"


def test_client_application_defaults_for_service_client():
    client = ClientApplication.model_validate(
        {
            "client_id": "0oaxqwda3tluz4Aom697",
            "client_id_issued_at": 1763987048,
            "client_secret_expires_at": 0,
            "client_name": "OktaHound2",
            "client_uri": None,
            "logo_uri": None,
            "redirect_uris": [],
            "response_types": ["token"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "service",
        }
    )

    assert client.post_logout_redirect_uris == []
    assert client.initiate_login_uri is None
    assert client.software_id is None
