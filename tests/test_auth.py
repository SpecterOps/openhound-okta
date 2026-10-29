from base64 import b64encode
import os
import subprocess
import sys
from threading import Event, Lock, Thread

import pytest
import requests
from dlt.sources.helpers import requests as dlt_requests
from dlt.sources.helpers.requests.retry import Client
from pydantic import ValidationError
from requests import Request
from requests.adapters import HTTPAdapter

import openhound_okta.utils.auth as auth_module
from openhound_okta.utils.auth import (
    DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
    OKTA_DEFAULT_SCOPE,
    OktaAppCredentials,
    OktaAuth,
    OktaBearerAuth,
    OktaClientSecretCredentials,
    OktaEncodedAppCredentials,
    OktaTokenCredentials,
    Token,
)


class FakeClock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _token(access_token: str, expires_in: int = 3600) -> Token:
    return Token(
        access_token=access_token,
        token_type="Bearer",
        expires_in=expires_in,
        scope="okta.users.read",
    )


def _http_error(status_code: int) -> requests.HTTPError:
    response = requests.Response()
    response.status_code = status_code
    response.url = "https://example.okta.test/oauth2/v1/token"
    return requests.HTTPError(response=response)


def _client_secret_credentials(
    base_url: str = "https://example.okta.test",
) -> OktaClientSecretCredentials:
    """Build client secret credentials for the token request tests."""
    return OktaClientSecretCredentials(
        base_url=base_url,
        client_id="client-1",
        client_secret="secret-1",
    )


def test_okta_auth_requires_private_key_source():
    with pytest.raises(ValueError, match="private_key_path or private_key_string"):
        OktaAuth()


def test_token_masks_access_token_in_repr_and_str():
    """A logged Token shows a masked access token, never the real one."""
    token = _token("token-1")

    assert "token-1" not in repr(token)
    assert "token-1" not in str(token)
    assert token.access_token.get_secret_value() == "token-1"


def test_cached_bearer_token_omits_access_token_from_repr():
    """A logged cache entry shows only its refresh schedule."""
    auth = OktaBearerAuth(lambda: _token("token-1"))

    assert auth.authorization_header() == "Bearer token-1"
    assert "token-1" not in repr(auth._cached_token)


def _retrying_token_client(
    monkeypatch, status_codes: list[int], *, max_attempts: int
) -> list[str]:
    """Route token requests through a real dlt retry client without sleeping.

    Args:
        monkeypatch: pytest fixture used to patch the HTTP adapter and dlt client.
        status_codes: HTTP status answered to each attempt, in order.
        max_attempts: Retry budget of the dlt client.

    Returns:
        The Authorization header of every HTTP attempt, appended as requests are made.
    """
    authorization_headers: list[str] = []

    def send(self, request, **kwargs):
        authorization_headers.append(request.headers["Authorization"])
        response = requests.Response()
        response.status_code = status_codes[len(authorization_headers) - 1]
        response._content = (
            b'{"access_token":"token-1","token_type":"Bearer",'
            b'"expires_in":3600,"scope":"okta.users.read"}'
            if response.status_code == 200
            else b'{"error":"server_error"}'
        )
        response.url = request.url
        response.request = request
        return response

    monkeypatch.setattr(HTTPAdapter, "send", send)
    client = Client(request_max_attempts=max_attempts, request_backoff_factor=0)
    monkeypatch.setattr(dlt_requests, "post", client.post)
    return authorization_headers


def test_token_request_retries_transient_failures(monkeypatch):
    """A 5xx token response is retried, resending the Basic credentials each time."""
    authorization_headers = _retrying_token_client(
        monkeypatch, [503, 503, 200], max_attempts=3
    )

    token = _client_secret_credentials().fetch_token()

    assert token == _token("token-1")
    assert authorization_headers == ["Basic Y2xpZW50LTE6c2VjcmV0LTE="] * 3


def test_token_request_reraises_http_error_after_retries_run_out(monkeypatch):
    """Exhausted retries surface the final HTTPError so OktaBearerAuth can classify it."""
    authorization_headers = _retrying_token_client(
        monkeypatch, [503, 503], max_attempts=2
    )

    with pytest.raises(requests.HTTPError) as error:
        _client_secret_credentials().fetch_token()

    assert error.value.response.status_code == 503
    assert len(authorization_headers) == 2


def test_client_secret_token_response_rejects_plain_http(monkeypatch):
    """The client secret is never sent to a token endpoint that is not HTTPS."""

    def post(*args, **kwargs):
        raise AssertionError("no request may be sent over plain HTTP")

    monkeypatch.setattr("openhound_okta.utils.auth.dlt_requests.post", post)

    with pytest.raises(ValueError, match="https"):
        _client_secret_credentials("http://example.okta.test").fetch_token()


def test_client_secret_token_response_uses_http_basic_auth(monkeypatch):
    """The grant carries only grant_type and scope; the secret rides in Basic auth."""
    requested: list[tuple[str, dict[str, object]]] = []
    response = requests.Response()
    response.status_code = 200
    response._content = (
        b'{"access_token":"token-1","token_type":"Bearer",'
        b'"expires_in":3600,"scope":"okta.users.read"}'
    )

    def post(url: str, **kwargs):
        requested.append((url, kwargs))
        return response

    monkeypatch.setattr("openhound_okta.utils.auth.dlt_requests.post", post)

    token = _client_secret_credentials().fetch_token()

    assert token == _token("token-1")
    assert requested[0][0] == "https://example.okta.test/oauth2/v1/token"
    assert requested[0][1]["data"] == {
        "grant_type": "client_credentials",
        "scope": " ".join(OKTA_DEFAULT_SCOPE),
    }
    assert "secret-1" not in repr(requested[0][1]["data"])
    assert requested[0][1]["timeout"] == DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS

    # Apply the auth handler to prove the prepared request receives exactly the
    # Basic credentials Okta requires, without exposing them in the form data.
    request = Request("POST", requested[0][0]).prepare()
    requested[0][1]["auth"](request)
    assert request.headers["Authorization"] == "Basic Y2xpZW50LTE6c2VjcmV0LTE="


def test_client_secret_token_response_does_not_expose_secret_on_http_error(
    monkeypatch,
):
    """An HTTPError raised for a rejected token request does not contain the secret."""
    response = requests.Response()
    response.status_code = 401
    response.url = "https://example.okta.test/oauth2/v1/token"
    response._content = b'{"error":"invalid_client"}'

    def post(url: str, **kwargs):
        # Apply the supplied auth handler so the failure exercises a realistic
        # prepared request whose Authorization header contains the secret.
        response.request = Request("POST", url, auth=kwargs["auth"]).prepare()
        return response

    monkeypatch.setattr("openhound_okta.utils.auth.dlt_requests.post", post)

    with pytest.raises(requests.HTTPError) as error:
        OktaClientSecretCredentials(
            base_url="https://example.okta.test",
            client_id="client-1",
            client_secret="secret-that-must-not-leak",
        ).fetch_token()

    assert "secret-that-must-not-leak" not in str(error.value)
    assert "secret-that-must-not-leak" not in repr(error.value)


def test_client_secret_token_response_rejects_malformed_success_payload(monkeypatch):
    """An incomplete token payload fails validation without echoing the token."""
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"access_token":"token-1"}'

    monkeypatch.setattr(
        "openhound_okta.utils.auth.dlt_requests.post",
        lambda *args, **kwargs: response,
    )

    with pytest.raises(ValidationError) as error:
        _client_secret_credentials().fetch_token()

    assert "token-1" not in str(error.value)


def test_client_secret_token_response_propagates_timeout(monkeypatch):
    """A timeout from the retrying client propagates unchanged."""

    def post(*args, **kwargs):
        raise requests.Timeout("token endpoint unavailable")

    monkeypatch.setattr("openhound_okta.utils.auth.dlt_requests.post", post)

    with pytest.raises(requests.Timeout, match="token endpoint unavailable"):
        _client_secret_credentials().fetch_token()


def test_okta_bearer_auth_requires_non_negative_refresh_skew():
    with pytest.raises(ValueError, match="refresh_skew_seconds cannot be negative"):
        OktaBearerAuth(lambda: _token("token-1"), refresh_skew_seconds=-1)


@pytest.mark.parametrize(
    "refresh_skew_seconds", [float("nan"), float("inf"), float("-inf")]
)
def test_okta_bearer_auth_requires_finite_refresh_skew(refresh_skew_seconds):
    with pytest.raises(ValueError, match="refresh_skew_seconds must be finite"):
        OktaBearerAuth(
            lambda: _token("token-1"),
            refresh_skew_seconds=refresh_skew_seconds,
        )


def test_okta_bearer_auth_requires_non_negative_refresh_failure_cooldown():
    with pytest.raises(
        ValueError,
        match="refresh_failure_cooldown_seconds cannot be negative",
    ):
        OktaBearerAuth(
            lambda: _token("token-1"),
            refresh_failure_cooldown_seconds=-1,
        )


@pytest.mark.parametrize(
    "refresh_failure_cooldown_seconds",
    [float("nan"), float("inf"), float("-inf")],
)
def test_okta_bearer_auth_requires_finite_refresh_failure_cooldown(
    refresh_failure_cooldown_seconds,
):
    with pytest.raises(
        ValueError,
        match="refresh_failure_cooldown_seconds must be finite",
    ):
        OktaBearerAuth(
            lambda: _token("token-1"),
            refresh_failure_cooldown_seconds=refresh_failure_cooldown_seconds,
        )


def test_okta_bearer_auth_reuses_cached_token_before_refresh_window():
    clock = FakeClock()
    fetched_tokens: list[str] = []

    def fetch_token() -> Token:
        fetched_tokens.append("token-1")
        return _token("token-1")

    auth = OktaBearerAuth(fetch_token, clock=clock)
    request = Request("GET", "https://example.okta.test/api/v1/users").prepare()

    auth(request)
    clock.now += 3_299.0

    assert auth.authorization_header() == "Bearer token-1"
    assert request.headers["Authorization"] == "Bearer token-1"
    assert fetched_tokens == ["token-1"]


def test_okta_bearer_auth_refreshes_inside_skew_window():
    clock = FakeClock()
    fetched_tokens = iter([_token("token-1"), _token("token-2")])

    auth = OktaBearerAuth(lambda: next(fetched_tokens), clock=clock)

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 3_300.0

    assert auth.authorization_header() == "Bearer token-2"


def test_okta_bearer_auth_reuses_unexpired_token_when_proactive_refresh_fails():
    clock = FakeClock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return _token("token-1", expires_in=10)
        raise requests.Timeout("token endpoint unavailable")

    auth = OktaBearerAuth(
        fetch_token,
        refresh_failure_cooldown_seconds=30,
        clock=clock,
    )

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 5.0
    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 5.0
    with pytest.raises(requests.Timeout, match="token endpoint unavailable"):
        auth.authorization_header()

    assert fetch_count == 3


def test_okta_bearer_auth_retries_proactive_refresh_after_failure_cooldown():
    clock = FakeClock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return _token("token-1", expires_in=20)
        if fetch_count == 2:
            raise requests.ConnectionError("token endpoint unavailable")
        return _token("token-2", expires_in=20)

    auth = OktaBearerAuth(
        fetch_token,
        refresh_failure_cooldown_seconds=5,
        clock=clock,
    )

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 10.0
    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 4.9
    assert auth.authorization_header() == "Bearer token-1"
    assert fetch_count == 2

    clock.now += 0.1
    assert auth.authorization_header() == "Bearer token-2"
    assert fetch_count == 3


def test_okta_bearer_auth_does_not_reuse_token_that_expires_during_failed_refresh():
    clock = FakeClock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return _token("token-1", expires_in=10)
        clock.now += 5.0
        raise requests.Timeout("token endpoint unavailable")

    auth = OktaBearerAuth(fetch_token, clock=clock)

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 5.0
    with pytest.raises(requests.Timeout, match="token endpoint unavailable"):
        auth.authorization_header()

    assert fetch_count == 2


def test_okta_bearer_auth_shares_proactive_refresh_failure_cooldown_across_callers():
    clock = FakeClock()
    refresh_started = Event()
    release_refresh = Event()
    count_lock = Lock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        with count_lock:
            fetch_count += 1
            current_fetch = fetch_count
        if current_fetch == 1:
            return _token("token-1", expires_in=20)

        refresh_started.set()
        assert release_refresh.wait(timeout=1.0)
        raise requests.Timeout("token endpoint unavailable")

    auth = OktaBearerAuth(
        fetch_token,
        refresh_failure_cooldown_seconds=5,
        clock=clock,
    )

    assert auth.authorization_header() == "Bearer token-1"
    clock.now += 10.0

    headers: list[str] = []
    errors: list[Exception] = []

    def read_header() -> None:
        try:
            headers.append(auth.authorization_header())
        except Exception as exc:
            errors.append(exc)

    threads = [Thread(target=read_header) for _ in range(4)]
    for thread in threads:
        thread.start()

    assert refresh_started.wait(timeout=1.0)
    release_refresh.set()

    for thread in threads:
        thread.join(timeout=1.0)
        assert not thread.is_alive()

    assert errors == []
    assert fetch_count == 2
    assert headers == ["Bearer token-1"] * 4


@pytest.mark.parametrize("status_code", [429, 500])
def test_okta_bearer_auth_reuses_unexpired_token_after_transient_http_refresh_failure(
    status_code,
):
    clock = FakeClock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return _token("token-1", expires_in=10)
        raise _http_error(status_code)

    auth = OktaBearerAuth(fetch_token, clock=clock)

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 5.0
    assert auth.authorization_header() == "Bearer token-1"
    assert fetch_count == 2


def test_okta_bearer_auth_does_not_reuse_unexpired_token_after_non_transient_refresh_failure():
    clock = FakeClock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        fetch_count += 1
        if fetch_count == 1:
            return _token("token-1", expires_in=10)
        raise _http_error(400)

    auth = OktaBearerAuth(fetch_token, clock=clock)

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 5.0
    with pytest.raises(requests.HTTPError):
        auth.authorization_header()

    assert fetch_count == 2


def test_okta_bearer_auth_reuses_short_lived_token_until_half_life():
    clock = FakeClock()
    fetched_tokens = iter([_token("token-1", expires_in=10), _token("token-2")])
    auth = OktaBearerAuth(lambda: next(fetched_tokens), clock=clock)

    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 4.9
    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 0.1
    assert auth.authorization_header() == "Bearer token-2"


def test_okta_bearer_auth_starts_short_lived_refresh_window_after_fetch_completes():
    clock = FakeClock()
    fetched_tokens: list[str] = []

    def fetch_token() -> Token:
        access_token = f"token-{len(fetched_tokens) + 1}"
        fetched_tokens.append(access_token)
        if access_token == "token-1":
            clock.now += 6.0
        return _token(access_token, expires_in=10)

    auth = OktaBearerAuth(fetch_token, clock=clock)

    assert auth.authorization_header() == "Bearer token-1"
    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 4.9
    assert auth.authorization_header() == "Bearer token-1"

    clock.now += 0.1
    assert auth.authorization_header() == "Bearer token-2"
    assert fetched_tokens == ["token-1", "token-2"]


def test_okta_bearer_auth_only_invalidates_matching_token():
    fetched_tokens = iter([_token("token-1"), _token("token-2")])
    auth = OktaBearerAuth(lambda: next(fetched_tokens))

    assert auth.authorization_header() == "Bearer token-1"
    assert auth.invalidate("stale-token") is False
    assert auth.authorization_header() == "Bearer token-1"
    assert auth.invalidate("token-1") is True
    assert auth.authorization_header() == "Bearer token-2"


def test_okta_bearer_auth_refreshes_once_for_concurrent_callers():
    refresh_started = Event()
    release_refresh = Event()
    count_lock = Lock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        with count_lock:
            fetch_count += 1
        refresh_started.set()
        assert release_refresh.wait(timeout=1.0)
        return _token("token-1")

    auth = OktaBearerAuth(fetch_token)
    headers: list[str] = []

    def read_header() -> None:
        headers.append(auth.authorization_header())

    threads = [Thread(target=read_header) for _ in range(4)]
    for thread in threads:
        thread.start()

    assert refresh_started.wait(timeout=1.0)
    release_refresh.set()

    for thread in threads:
        thread.join(timeout=1.0)
        assert not thread.is_alive()

    assert fetch_count == 1
    assert headers == ["Bearer token-1"] * 4


def test_okta_bearer_auth_expired_token_refreshes_once_for_concurrent_callers():
    clock = FakeClock()
    refresh_started = Event()
    release_refresh = Event()
    count_lock = Lock()
    fetch_count = 0

    def fetch_token() -> Token:
        nonlocal fetch_count
        with count_lock:
            fetch_count += 1
            current_fetch = fetch_count
        if current_fetch == 1:
            return _token("token-1", expires_in=10)

        refresh_started.set()
        assert release_refresh.wait(timeout=1.0)
        return _token("token-2", expires_in=10)

    auth = OktaBearerAuth(fetch_token, refresh_skew_seconds=0, clock=clock)

    assert auth.authorization_header() == "Bearer token-1"
    clock.now += 10.0

    headers: list[str] = []

    def read_header() -> None:
        headers.append(auth.authorization_header())

    threads = [Thread(target=read_header) for _ in range(4)]
    for thread in threads:
        thread.start()

    assert refresh_started.wait(timeout=1.0)
    release_refresh.set()

    for thread in threads:
        thread.join(timeout=1.0)
        assert not thread.is_alive()

    assert fetch_count == 2
    assert headers == ["Bearer token-2"] * 4


@pytest.mark.parametrize(
    ("credentials", "expected_init_kwargs"),
    [
        (
            OktaAppCredentials(
                base_url="https://example.okta.test",
                private_key_path="/tmp/private-key.json",
                client_id="client-1",
            ),
            {"private_key_path": "/tmp/private-key.json"},
        ),
        (
            OktaEncodedAppCredentials(
                base_url="https://example.okta.test",
                private_key_b64=b64encode(b'{"kid":"kid-1"}').decode("ascii"),
                client_id="client-1",
            ),
            {"private_key_string": '{"kid":"kid-1"}'},
        ),
    ],
)
def test_private_key_credentials_post_signed_client_assertion(
    monkeypatch, credentials, expected_init_kwargs
):
    """Private key credentials sign a client assertion and post the private_key_jwt grant."""
    calls: list[tuple[str, object]] = []
    requested: list[tuple[str, dict[str, object]]] = []
    response = requests.Response()
    response.status_code = 200
    response._content = (
        b'{"access_token":"token-1","token_type":"Bearer",'
        b'"expires_in":3600,"scope":"okta.users.read"}'
    )

    class StubOktaAuth:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        @property
        def private_key(self):
            calls.append(("private_key", None))
            return {"kid": "kid-1"}

        def jwt(self, **kwargs):
            calls.append(("jwt", kwargs))
            return "client-assertion"

    def post(url: str, **kwargs):
        requested.append((url, kwargs))
        return response

    monkeypatch.setattr(auth_module, "OktaAuth", StubOktaAuth)
    monkeypatch.setattr("openhound_okta.utils.auth.dlt_requests.post", post)

    token = credentials.fetch_token()

    assert token == _token("token-1")
    assert calls == [
        ("init", expected_init_kwargs),
        ("private_key", None),
        (
            "jwt",
            {
                "private_key": {"kid": "kid-1"},
                "client_id": "client-1",
                "audience": "https://example.okta.test/oauth2/v1/token",
                "exp_delta": 60,
            },
        ),
    ]
    assert requested == [
        (
            "https://example.okta.test/oauth2/v1/token",
            {
                "headers": {
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                    "cache-control": "no-cache",
                },
                "data": {
                    "grant_type": "client_credentials",
                    "scope": " ".join(OKTA_DEFAULT_SCOPE),
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": "client-assertion",
                },
                "auth": None,
                "timeout": DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
            },
        )
    ]


def test_request_auth_uses_lazy_refreshable_auth_for_app_credentials():
    credentials = OktaAppCredentials(
        base_url="https://example.okta.test",
        private_key_path="/tmp/not-read-during-auth-construction.json",
        client_id="client-1",
    )

    auth = credentials.request_auth()

    assert isinstance(auth, OktaBearerAuth)


def test_request_auth_uses_refreshable_auth_for_client_secret_credentials():
    """Client secret credentials share the refreshing bearer-token lifecycle."""
    auth = _client_secret_credentials().request_auth()

    assert isinstance(auth, OktaBearerAuth)


def test_source_resolves_client_secret_credentials_from_environment(tmp_path):
    """dlt picks the client secret spec from the credentials union documented in the README."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SOURCES__")
    }
    environment.update(
        {
            # Keep the developer's global ~/.dlt/secrets.toml out of the union
            # resolution: dlt derives its global folder from the home directory.
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "RUNTIME__LOG_PATH": str(tmp_path / "logs"),
            "SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL": (
                "https://example.okta.test"
            ),
            "SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_ID": "client-1",
            "SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_SECRET": "secret-1",
        }
    )
    probe = """
import openhound_okta.source as source_module
import openhound_okta.utils.auth as auth_module

resolved_credentials = []
# Intercept auth construction on every credential kind to record which one
# dlt resolved from the environment.
for spec in (auth_module.OktaOAuthCredentials, auth_module.OktaTokenCredentials):
    spec.request_auth = lambda self: resolved_credentials.append(self)
source_module.source()
credentials = resolved_credentials[0]
print(type(credentials).__name__)
print(credentials.base_url)
print(credentials.client_id)
print(credentials.client_secret)
"""

    # DLT records its project directory during import. A fresh process makes
    # this an environment-only resolution test and matches collector startup.
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=True,
        text=True,
    )

    assert result.stdout.splitlines() == [
        "OktaClientSecretCredentials",
        "https://example.okta.test",
        "client-1",
        "secret-1",
    ]


def test_request_auth_keeps_static_header_auth_for_ssws_tokens():
    auth = OktaTokenCredentials(
        base_url="https://example.okta.test",
        token="ssws-token",
    ).request_auth()
    request = Request("GET", "https://example.okta.test/api/v1/users").prepare()

    auth(request)

    assert request.headers["Authorization"] == "SSWS ssws-token"
