from openhound_okta.models import ClientApplication


def test_application_accepts_jwk_without_kid():
    """Regression test for OAuth clients whose embedded JWKS has a key without a kid.

    The ``kid`` member is optional in RFC 7517, and Okta accepts keys registered
    through the Apps API or dynamic client registration without one. Such keys
    come back from GET /oauth2/v1/clients with ``kid: null`` (or absent). The
    client model previously required ``kid``, so DLT discarded the whole client
    row during validation and the client's role assignments never reached the
    graph. Only ``client_id`` and ``application_type`` are read from this model,
    so a missing ``kid`` must not reject the client.
    """
    client = ClientApplication.model_validate(
        {
            "client_id": "0oa1client",
            "application_type": "service",
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {
                "keys": [
                    {
                        "kid": None,
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "n": "iKqiD4cr7FZKm6f05K4r",
                        "e": "AQAB",
                    },
                    {
                        "kty": "RSA",
                        "id": "pksw0pu008JFcIkT5697",
                        "use": "sig",
                        "n": "iKqiD4cr7FZKm6f05K4r",
                        "e": "AQAB",
                    },
                ]
            },
        }
    )

    assert client.client_id == "0oa1client"
    assert [key.kid for key in client.jwks.keys] == [None, None]
    assert client.jwks.keys[0].alg == "RS256"
    assert client.jwks.keys[0].e == "AQAB"
    assert client.jwks.keys[0].id is None
    assert client.jwks.keys[1].id == "pksw0pu008JFcIkT5697"
