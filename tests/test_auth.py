from base64 import b64encode
from threading import Event, Lock, Thread

import pytest
import requests
from pydantic import ValidationError
from requests import Request

import openhound_okta.source as source_module
from openhound_okta.models.token import Token
from openhound_okta.source import (
    OktaAppCredentials,
    OktaEncodedAppCredentials,
    OktaTokenCredentials,
    _request_auth,
)
from openhound_okta.utils.auth import (
    DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
    OktaAuth,
    OktaBearerAuth,
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


def test_okta_auth_requires_private_key_source():
    with pytest.raises(ValueError, match="private_key_path or private_key_string"):
        OktaAuth()


def test_okta_auth_token_response_uses_timeout_and_validates_status(monkeypatch):
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

    monkeypatch.setattr("openhound_okta.utils.auth.requests.post", post)

    token = OktaAuth(private_key_string='{"kid":"kid-1"}').token_response(
        "https://example.okta.test",
        "client-assertion",
        "okta.users.read",
    )

    assert token == _token("token-1")
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
                    "scope": "okta.users.read",
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": "client-assertion",
                },
                "timeout": DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
            },
        )
    ]


def test_okta_auth_token_response_raises_http_error_before_parsing(monkeypatch):
    response = requests.Response()
    response.status_code = 500
    response.url = "https://example.okta.test/oauth2/v1/token"
    response._content = b'{"error":"server_error"}'

    monkeypatch.setattr(
        "openhound_okta.utils.auth.requests.post",
        lambda *args, **kwargs: response,
    )

    with pytest.raises(requests.HTTPError):
        OktaAuth(private_key_string='{"kid":"kid-1"}').token_response(
            "https://example.okta.test",
            "client-assertion",
            "okta.users.read",
        )


def test_okta_auth_token_response_rejects_malformed_success_payload(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"access_token":"token-1"}'

    monkeypatch.setattr(
        "openhound_okta.utils.auth.requests.post",
        lambda *args, **kwargs: response,
    )

    with pytest.raises(ValidationError):
        OktaAuth(private_key_string='{"kid":"kid-1"}').token_response(
            "https://example.okta.test",
            "client-assertion",
            "okta.users.read",
        )


def test_okta_bearer_auth_requires_non_negative_refresh_skew():
    with pytest.raises(ValueError, match="refresh_skew_seconds cannot be negative"):
        OktaBearerAuth(lambda: _token("token-1"), refresh_skew_seconds=-1)


@pytest.mark.parametrize("refresh_skew_seconds", [float("nan"), float("inf"), float("-inf")])
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
def test_app_credentials_fetch_full_token_metadata(
    monkeypatch, credentials, expected_init_kwargs
):
    calls: list[tuple[str, object]] = []

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

        def token_response(self, base_url, jwt, scope):
            calls.append(("token_response", (base_url, jwt, scope)))
            return _token("token-1")

    monkeypatch.setattr(source_module, "OktaAuth", StubOktaAuth)

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
        (
            "token_response",
            (
                "https://example.okta.test",
                "client-assertion",
                " ".join(source_module.OKTA_DEFAULT_SCOPE),
            ),
        ),
    ]


def test_request_auth_uses_lazy_refreshable_auth_for_app_credentials():
    credentials = OktaAppCredentials(
        base_url="https://example.okta.test",
        private_key_path="/tmp/not-read-during-auth-construction.json",
        client_id="client-1",
    )

    auth = _request_auth(credentials)

    assert isinstance(auth, OktaBearerAuth)


def test_request_auth_keeps_static_header_auth_for_ssws_tokens():
    auth = _request_auth(
        OktaTokenCredentials(
            base_url="https://example.okta.test",
            token="ssws-token",
        )
    )
    request = Request("GET", "https://example.okta.test/api/v1/users").prepare()

    auth(request)

    assert request.headers["Authorization"] == "SSWS ssws-token"
