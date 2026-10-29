"""Okta authentication: access token requests and the shared bearer-token lifecycle."""

import json
import logging
import math
import re
import time
from base64 import b64decode
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Final, Union
from urllib.parse import urlparse

import dlt
import requests
from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration
from dlt.common.typing import TSecretStrValue
from dlt.sources.helpers import requests as dlt_requests
from dlt.sources.helpers.rest_client.auth import APIKeyAuth
from joserfc import jwt
from joserfc.jwk import RSAKey
from pydantic import BaseModel, ConfigDict, SecretStr
from requests.auth import AuthBase, HTTPBasicAuth
from requests.models import PreparedRequest

logger = logging.getLogger(__name__)

# Seconds before expiry at which a bearer token is refreshed proactively, so
# in-flight pagination never runs into an expired token. Capped at half the
# token lifetime for short-lived tokens.
DEFAULT_BEARER_REFRESH_SKEW_SECONDS: Final[float] = 300.0
# Seconds to keep using a still-valid token after a transient refresh failure
# before the next refresh attempt, so every caller does not hammer the token
# endpoint while it is unavailable.
DEFAULT_BEARER_REFRESH_FAILURE_COOLDOWN_SECONDS: Final[float] = 5.0
# Timeout of each token request attempt to the org authorization server.
DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS: Final[float] = 10.0
# Headers of every request to the org authorization server's token endpoint.
TOKEN_REQUEST_HEADERS: Final[dict[str, str]] = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "cache-control": "no-cache",
}
# Okta API scopes requested for every OAuth 2.0 access token; the collector's
# service app or API Service Integration must have exactly these granted.
OKTA_DEFAULT_SCOPE: Final[list[str]] = [
    "okta.users.read",
    "okta.apps.read",
    "okta.groups.read",
    "okta.roles.read",
    "okta.agentPools.read",
    "okta.apiTokens.read",
    "okta.authorizationServers.read",
    "okta.devices.read",
    "okta.policies.read",
    "okta.orgs.read",
    "okta.idps.read",
    "okta.features.read",
    "okta.clients.read",
    "okta.appGrants.read",
    "okta.oauthIntegrations.read",
    "okta.authenticators.read",
    # Optional scopes which require a dedicated license
    "okta.realms.read",
    "okta.realmAssignments.read",
]


@dataclass(frozen=True)
class _CachedBearerToken:
    """Bearer token held by OktaBearerAuth together with its refresh schedule.

    Attributes:
        access_token: The bearer token string.
        refresh_at: Monotonic time at which a proactive refresh is due.
        expires_at: Monotonic time at which Okta stops accepting the token.
    """

    # Excluded from repr so an accidental log of the cache entry shows only the
    # timestamps, never the token.
    access_token: str = field(repr=False)
    refresh_at: float
    expires_at: float


class UnauthorizedClassification(Enum):
    INVALID_TOKEN = "invalid_token"
    NON_TOKEN = "non_token"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class UnauthorizedDecision:
    """Outcome of handling an HTTP 401 for a bearer-authenticated request.

    Attributes:
        retry: Whether the request should be retried with the current token.
        invalidated: Whether the shared token cache was cleared.
        reason: Short machine-readable reason for logs and telemetry.
        classification: How the 401 was interpreted.
    """

    retry: bool
    invalidated: bool
    reason: str
    classification: UnauthorizedClassification


class Token(BaseModel):
    """OAuth 2.0 token response from the Okta org authorization server.

    Attributes:
        access_token: Bearer token for collection requests.
        token_type: Token type reported by Okta, always "Bearer".
        expires_in: Token lifetime in seconds.
        scope: Space-separated scopes actually granted.
    """

    # Validation errors echo the offending input by default, which would copy a
    # live access token into tracebacks and logs.
    model_config = ConfigDict(hide_input_in_errors=True)

    # SecretStr masks the token in repr, str and serialization; callers must
    # ask for it explicitly with get_secret_value().
    access_token: SecretStr
    token_type: str
    expires_in: int
    scope: str


@dataclass(frozen=True)
class ClientCredentialsGrant:
    """Form body of a client_credentials grant to the Okta token endpoint.

    Attributes:
        scopes: Okta API scopes to request.
        client_assertion: Signed JWT authenticating the client (private_key_jwt),
            or None when the client authenticates through request headers.
    """

    scopes: Sequence[str]
    client_assertion: str | None = None

    def form(self) -> dict[str, str]:
        """Render the grant as application/x-www-form-urlencoded fields.

        Returns:
            The form fields for the token request body, with the scopes joined
            into the space-separated `scope` parameter OAuth 2.0 expects.
        """
        fields = {"grant_type": "client_credentials", "scope": " ".join(self.scopes)}
        if self.client_assertion is not None:
            # RFC 7523 client authentication with a signed JWT (private_key_jwt).
            fields["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            fields["client_assertion"] = self.client_assertion
        return fields


def response_bearer_token(response: requests.Response) -> str | None:
    """Extract the bearer token the request behind `response` was sent with.

    Args:
        response: A response whose prepared request may carry an
            `Authorization: Bearer` header.

    Returns:
        The bearer token, or None if the request did not use bearer auth.
    """
    prepared_request = getattr(response, "request", None)
    headers = getattr(prepared_request, "headers", None)
    if headers is None:
        return None

    authorization = headers.get("Authorization")
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return None

    access_token = authorization.removeprefix("Bearer ")
    return access_token or None


def classify_unauthorized(response: requests.Response) -> UnauthorizedClassification:
    """Tell whether an Okta HTTP 401 blames the bearer token itself.

    Okta signals an expired or revoked token with `error="invalid_token"` in the
    WWW-Authenticate challenge or error code E0000011 in the body, and a token
    that is valid but lacks scope with `insufficient_scope` or E0000015. Only
    the former warrants rotating the token.

    Args:
        response: The HTTP 401 response.

    Returns:
        INVALID_TOKEN, NON_TOKEN, or UNKNOWN when neither signal is present.
    """
    challenge = response.headers.get("WWW-Authenticate", "")
    if re.search(r'\berror\s*=\s*"?invalid_token"?', challenge, re.IGNORECASE):
        return UnauthorizedClassification.INVALID_TOKEN
    if re.search(r'\berror\s*=\s*"?insufficient_scope"?', challenge, re.IGNORECASE):
        return UnauthorizedClassification.NON_TOKEN

    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        error_code = payload.get("errorCode")
        if error_code == "E0000011":
            return UnauthorizedClassification.INVALID_TOKEN
        if error_code == "E0000015":
            return UnauthorizedClassification.NON_TOKEN

    return UnauthorizedClassification.UNKNOWN


def _base_url_hostname(base_url: str) -> str:
    """Validate the Okta org base URL and return its hostname.

    This is the single rule for what a usable base URL is: a parseable HTTPS
    URL with a hostname. Okta serves everything over HTTPS only, so any other
    scheme is a misconfiguration that must fail before credentials leave the
    process.

    Args:
        base_url: Okta org base URL.

    Returns:
        The hostname exactly as written in the URL.

    Raises:
        ValueError: The URL is missing, malformed, lacks a scheme or hostname,
            or does not use https.
    """
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Okta base URL is unavailable")
    try:
        parsed = urlparse(base_url.strip())
        _ = parsed.port  # Raises for a malformed port.
        hostname = parsed.hostname
    except ValueError as error:
        raise ValueError(
            "Okta base URL must include a URL scheme and hostname"
        ) from error
    if not parsed.scheme or not hostname:
        raise ValueError("Okta base URL must include a URL scheme and hostname")
    if parsed.scheme.casefold() != "https":
        raise ValueError("Okta base URL must use the https scheme")
    return hostname


def _request_token(
    base_url: str,
    grant: ClientCredentialsGrant,
    auth: AuthBase | None = None,
) -> Token:
    """POST a client_credentials grant to the org authorization server.

    The request goes through dlt's retrying HTTP client, so HTTP 429, HTTP 5xx,
    connection errors and timeouts are retried with exponential backoff and
    Retry-After support under dlt's `runtime.request_*` settings, in line with
    the collector's other requests. The last failure is re-raised unchanged,
    which lets OktaBearerAuth tell transient refresh failures apart.

    Args:
        base_url: Okta org base URL; must be HTTPS.
        grant: The grant to send; carries the client assertion when the client
            authenticates in the body.
        auth: Optional requests auth handler that authenticates the client
            through headers, keeping its secret out of the form body.

    Returns:
        The validated token response.

    Raises:
        ValueError: `base_url` is not a valid HTTPS URL.
        requests.HTTPError: Okta rejected the request, or retries ran out.
        requests.RequestException: The endpoint stayed unreachable.
        pydantic.ValidationError: The payload is not a valid token response.
    """
    _base_url_hostname(base_url)
    response = dlt_requests.post(
        f"{base_url}/oauth2/v1/token",
        headers=TOKEN_REQUEST_HEADERS,
        data=grant.form(),
        auth=auth,
        timeout=DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return Token.model_validate(response.json())


class OktaBearerAuth(AuthBase):
    """Requests auth handler that shares and refreshes an Okta bearer token."""

    def __init__(
        self,
        token_fetcher: Callable[[], Token],
        *,
        refresh_skew_seconds: float = DEFAULT_BEARER_REFRESH_SKEW_SECONDS,
        refresh_failure_cooldown_seconds: float = (
            DEFAULT_BEARER_REFRESH_FAILURE_COOLDOWN_SECONDS
        ),
        clock: Callable[[], float] = time.monotonic,
    ):
        if not math.isfinite(refresh_skew_seconds):
            raise ValueError("refresh_skew_seconds must be finite")
        if refresh_skew_seconds < 0:
            raise ValueError("refresh_skew_seconds cannot be negative")
        if not math.isfinite(refresh_failure_cooldown_seconds):
            raise ValueError("refresh_failure_cooldown_seconds must be finite")
        if refresh_failure_cooldown_seconds < 0:
            raise ValueError("refresh_failure_cooldown_seconds cannot be negative")

        self._token_fetcher = token_fetcher
        self._refresh_skew_seconds = refresh_skew_seconds
        self._refresh_failure_cooldown_seconds = refresh_failure_cooldown_seconds
        self._clock = clock
        self._lock = Lock()
        self._cached_token: _CachedBearerToken | None = None
        self._next_refresh_attempt_at = 0.0

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        request.headers["Authorization"] = self.authorization_header()
        return request

    def authorization_header(self) -> str:
        return f"Bearer {self._access_token()}"

    def invalidate(self, access_token: str | None = None) -> bool:
        """Clear the cached token if it still matches the failed request token."""
        with self._lock:
            cached_token = self._cached_token
            if cached_token is None:
                return False
            if access_token is not None and access_token != cached_token.access_token:
                return False

            self._cached_token = None
            self._next_refresh_attempt_at = 0.0
            return True

    def handle_unauthorized(
        self, response: requests.Response
    ) -> UnauthorizedDecision | None:
        """Decide whether a bearer 401 should rotate the shared token cache.

        Args:
            response: The HTTP 401 response, including the request it answers.

        Returns:
            The decision, or None when the failed request did not carry a
            bearer token and is therefore not this handler's concern.
        """
        failed_access_token = response_bearer_token(response)
        if failed_access_token is None:
            return None
        classification = classify_unauthorized(response)

        with self._lock:
            cached_token = self._cached_token
            if cached_token is None:
                return UnauthorizedDecision(
                    retry=True,
                    invalidated=False,
                    reason="refresh_in_progress",
                    classification=classification,
                )

            if failed_access_token != cached_token.access_token:
                return UnauthorizedDecision(
                    retry=True,
                    invalidated=False,
                    reason="stale_request_token",
                    classification=classification,
                )

            if classification is UnauthorizedClassification.NON_TOKEN:
                return UnauthorizedDecision(
                    retry=False,
                    invalidated=False,
                    reason="current_token_non_token_401",
                    classification=classification,
                )

            self._cached_token = None
            self._next_refresh_attempt_at = 0.0
            return UnauthorizedDecision(
                retry=True,
                invalidated=True,
                reason=(
                    "current_token_invalid"
                    if classification is UnauthorizedClassification.INVALID_TOKEN
                    else "current_token_unknown_401"
                ),
                classification=classification,
            )

    def _access_token(self) -> str:
        now = self._clock()
        cached_token = self._cached_token
        if cached_token is not None and self._is_fresh(cached_token, now):
            return cached_token.access_token

        with self._lock:
            now = self._clock()
            cached_token = self._cached_token
            if cached_token is not None and self._is_fresh(cached_token, now):
                return cached_token.access_token
            if (
                cached_token is not None
                and self._is_unexpired(cached_token, now)
                and now < self._next_refresh_attempt_at
            ):
                return cached_token.access_token

            try:
                response = self._token_fetcher()
            except Exception as exc:
                now = self._clock()
                if (
                    cached_token is not None
                    and self._is_unexpired(cached_token, now)
                    and self._is_transient_refresh_failure(exc)
                ):
                    self._next_refresh_attempt_at = (
                        now + self._refresh_failure_cooldown_seconds
                    )
                    logger.warning(
                        "Using cached Okta bearer token after proactive refresh failure; "
                        "token remains valid for %.2fs; next refresh attempt in %.2fs "
                        "refresh_error=%s",
                        cached_token.expires_at - now,
                        self._refresh_failure_cooldown_seconds,
                        exc.__class__.__name__,
                    )
                    return cached_token.access_token
                raise

            now = self._clock()
            lifetime = max(float(response.expires_in), 0.0)
            refresh_skew = min(self._refresh_skew_seconds, lifetime / 2.0)
            # Unwrap the SecretStr once, here, where the token must become a
            # header value; everything else keeps handling the masked form.
            access_token = response.access_token.get_secret_value()
            self._cached_token = _CachedBearerToken(
                access_token=access_token,
                refresh_at=now + lifetime - refresh_skew,
                expires_at=now + lifetime,
            )
            self._next_refresh_attempt_at = 0.0
            return access_token

    @staticmethod
    def _is_fresh(cached_token: _CachedBearerToken, now: float) -> bool:
        return now < cached_token.refresh_at

    @staticmethod
    def _is_unexpired(cached_token: _CachedBearerToken, now: float) -> bool:
        return now < cached_token.expires_at

    @staticmethod
    def _is_transient_refresh_failure(exc: Exception) -> bool:
        if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
            return True
        if not isinstance(exc, requests.HTTPError) or exc.response is None:
            return False
        return exc.response.status_code == 429 or exc.response.status_code >= 500


class OktaAuth:
    """Okta public/private key manager"""

    def __init__(
        self,
        private_key_path: str | None = None,
        private_key_string: str | None = None,
    ):
        if not private_key_path and not private_key_string:
            raise ValueError(
                "Either private_key_path or private_key_string must be configured"
            )
        self.private_key_path = Path(private_key_path) if private_key_path else None
        self.private_key_string = private_key_string

    def generate_private_key(self) -> None:
        """Generate a new private key and save it to the specified path."""
        if self.private_key_path is None:
            raise ValueError("private_key_path must be configured to generate a key")
        rsa_key = RSAKey.generate_key()
        private_key = rsa_key.as_pem(private=True)
        self.private_key_path.write_bytes(private_key)

    @property
    def private_key(self) -> dict:
        """Load the private key from the specified path."""

        if self.private_key_string:
            logger.info("Loaded private key from configured string")
            return json.loads(self.private_key_string)

        if self.private_key_path is None:
            raise ValueError("private_key_path must be configured")
        logger.info(f"Loaded private key from {self.private_key_path}")
        return json.loads(self.private_key_path.read_text())

    def jwt(
        self, private_key: dict, client_id: str, audience: str, exp_delta: int = 60
    ) -> str:
        """Returns a JWT token for Okta authentication

        Args:
            private_key (str): The private key used as string
            client_id (str): The application client id
            audience (str): The audience
            exp_delta (int, optional): The default expiry in minutes. Defaults to 60.

        Returns:
            str: The JWT token.
        """
        expire = int((datetime.now(UTC) + timedelta(minutes=exp_delta)).timestamp())
        header = {"alg": "RS256"}
        claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "exp": expire,
        }

        private_key_import = RSAKey.import_key(private_key)
        header["kid"] = private_key["kid"]
        jwt_token = jwt.encode(header=header, claims=claims, key=private_key_import)
        return jwt_token


@configspec
class OktaCredentials(CredentialsConfiguration):
    """Base of every Okta credential kind: the org base URL and what it is for.

    Concrete kinds decide how collection requests are authenticated by
    overriding `request_auth`.

    Attributes:
        base_url: Okta org base URL; must be HTTPS.
    """

    base_url: str = dlt.config.value

    def on_resolved(self) -> None:
        """Reject a malformed or plaintext-HTTP base URL as soon as dlt resolves it.

        Raises:
            ValueError: `base_url` is not a valid HTTPS URL.
        """
        _base_url_hostname(self.base_url)

    @property
    def tenant_domain(self) -> str:
        """Case-folded hostname of the Okta org, which scopes graph node IDs.

        Raises:
            ValueError: `base_url` is not a valid HTTPS URL.
        """
        return _base_url_hostname(self.base_url).casefold()

    def request_auth(self) -> AuthBase:
        """Build the requests auth handler for collection requests.

        Returns:
            The handler that authenticates each request.
        """
        raise NotImplementedError


@configspec
class OktaOAuthCredentials(OktaCredentials):
    """OAuth 2.0 client credentials grant for the collector's default scopes.

    Subclasses define how the client authenticates to the token endpoint:
    with a signed client assertion in the grant body, with a requests auth
    handler, or both. Collection requests then carry the bearer token,
    refreshed by OktaBearerAuth.

    Attributes:
        client_id: OAuth 2.0 client ID.
    """

    client_id: str = dlt.config.value

    def request_auth(self) -> AuthBase:
        """Build the shared, self-refreshing bearer auth for collection requests.

        Returns:
            An OktaBearerAuth that fetches tokens through `fetch_token`.
        """
        return OktaBearerAuth(self.fetch_token)

    def fetch_token(self) -> Token:
        """Request a fresh access token for the default scopes.

        Returns:
            The token response.

        Raises:
            ValueError: `base_url` is not a valid HTTPS URL.
            requests.RequestException: The token request failed after retries,
                or Okta rejected it.
            pydantic.ValidationError: Okta returned an invalid token payload.
        """
        return _request_token(
            self.base_url,
            ClientCredentialsGrant(
                scopes=OKTA_DEFAULT_SCOPE,
                client_assertion=self._client_assertion(),
            ),
            auth=self._grant_auth(),
        )

    def _client_assertion(self) -> str | None:
        """Signed JWT that authenticates the client in the grant body.

        Returns:
            None by default: the client does not authenticate in the body.
        """
        return None

    def _grant_auth(self) -> AuthBase | None:
        """Requests auth handler that authenticates the client through headers.

        Returns:
            None by default.
        """
        return None


@configspec
class OktaPrivateKeyCredentials(OktaOAuthCredentials):
    """Service app using the private_key_jwt method.

    The client assertion is a JWT signed with the app's private key (JWK);
    subclasses decide where the key comes from.
    """

    def _key_manager(self) -> OktaAuth:
        """Return the holder of the private key.

        Returns:
            An OktaAuth configured with this credential's key source.
        """
        raise NotImplementedError

    def _client_assertion(self) -> str:
        """Sign a client assertion for the token endpoint.

        Returns:
            The JWT, issued by and for the client ID, addressed to the token
            endpoint.

        Raises:
            KeyError: The private key JWK has no `kid`.
            ValueError: The private key is not JSON.
        """
        key_manager = self._key_manager()
        return key_manager.jwt(
            private_key=key_manager.private_key,
            client_id=self.client_id,
            audience=f"{self.base_url}/oauth2/v1/token",
            exp_delta=60,
        )


@configspec
class OktaAppCredentials(OktaPrivateKeyCredentials):
    """Service app credentials with the private key read from a file.

    Attributes:
        private_key_path: Path to the JWK JSON file.
    """

    private_key_path: TSecretStrValue = dlt.secrets.value

    def _key_manager(self) -> OktaAuth:
        """Return a key holder that reads the JWK from `private_key_path`.

        Returns:
            An OktaAuth bound to the key file.
        """
        return OktaAuth(private_key_path=self.private_key_path)


@configspec
class OktaEncodedAppCredentials(OktaPrivateKeyCredentials):
    """Service app credentials with the private key supplied base64-encoded.

    Attributes:
        private_key_b64: Base64-encoded JWK JSON.
    """

    private_key_b64: TSecretStrValue = dlt.secrets.value

    def _key_manager(self) -> OktaAuth:
        """Return a key holder for the decoded JWK.

        Returns:
            An OktaAuth bound to the decoded key string.

        Raises:
            binascii.Error: `private_key_b64` is not valid base64.
        """
        return OktaAuth(
            private_key_string=b64decode(self.private_key_b64).decode("utf-8")
        )


@configspec
class OktaClientSecretCredentials(OktaOAuthCredentials):
    """Client secret of an installed Okta API Service Integration.

    Only Okta Integration Network (OIN) API Service Integrations may obtain
    Okta API scopes with the client_secret_basic method. HTTPBasicAuth adds
    the secret to the Authorization header only while the token request is
    prepared, so it never enters the form body, the URL, logs, or validation
    errors.

    Attributes:
        client_secret: Client secret issued when the integration was installed.
    """

    client_secret: TSecretStrValue = dlt.secrets.value

    def _grant_auth(self) -> AuthBase:
        """Return HTTP Basic auth carrying the client ID and secret.

        Returns:
            The requests auth handler for the token request.
        """
        return HTTPBasicAuth(self.client_id, self.client_secret)


@configspec
class OktaTokenCredentials(OktaCredentials):
    """Static SSWS API token, acting as the administrator it was issued to.

    Attributes:
        token: The API token.
    """

    token: TSecretStrValue = dlt.secrets.value

    def request_auth(self) -> AuthBase:
        """Build a static header auth carrying the SSWS token.

        Returns:
            An APIKeyAuth setting the Authorization header on every request.
        """
        return APIKeyAuth(
            name="Authorization", api_key=f"SSWS {self.token}", location="header"
        )


# Every credential kind the source accepts; dlt resolves the first member whose
# fields are all present in the configured secrets.
AnyOktaCredentials = Union[
    OktaAppCredentials,
    OktaEncodedAppCredentials,
    OktaClientSecretCredentials,
    OktaTokenCredentials,
]
