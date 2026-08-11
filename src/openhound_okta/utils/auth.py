import json
import logging
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from threading import Lock

import requests
from joserfc import jwt
from joserfc.jwk import RSAKey
from requests.auth import AuthBase
from requests.models import PreparedRequest

from ..models.token import Token

logger = logging.getLogger(__name__)

DEFAULT_BEARER_REFRESH_SKEW_SECONDS = 300.0
DEFAULT_BEARER_REFRESH_FAILURE_COOLDOWN_SECONDS = 5.0
DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class _CachedBearerToken:
    access_token: str
    refresh_at: float
    expires_at: float


class UnauthorizedClassification(Enum):
    INVALID_TOKEN = "invalid_token"
    NON_TOKEN = "non_token"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class UnauthorizedDecision:
    retry: bool
    invalidated: bool
    reason: str


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
        self,
        failed_access_token: str,
        classification: UnauthorizedClassification,
    ) -> UnauthorizedDecision:
        """Decide whether a bearer 401 should rotate the shared token cache."""
        with self._lock:
            cached_token = self._cached_token
            if cached_token is None:
                return UnauthorizedDecision(
                    retry=True,
                    invalidated=False,
                    reason="refresh_in_progress",
                )

            if failed_access_token != cached_token.access_token:
                return UnauthorizedDecision(
                    retry=True,
                    invalidated=False,
                    reason="stale_request_token",
                )

            if classification is UnauthorizedClassification.NON_TOKEN:
                return UnauthorizedDecision(
                    retry=False,
                    invalidated=False,
                    reason="current_token_non_token_401",
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
            self._cached_token = _CachedBearerToken(
                access_token=response.access_token,
                refresh_at=now + lifetime - refresh_skew,
                expires_at=now + lifetime,
            )
            self._next_refresh_attempt_at = 0.0
            return response.access_token

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
            raise ValueError("Either private_key_path or private_key_string must be configured")
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

    def token_response(self, base_url: str, jwt: str, scope: str) -> Token:
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache",
        }

        data = {
            "grant_type": "client_credentials",
            "scope": scope,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt,
        }
        response = requests.post(
            f"{base_url}/oauth2/v1/token",
            headers=headers,
            data=data,
            timeout=DEFAULT_TOKEN_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return Token.model_validate(response.json())

    def token(self, base_url: str, jwt: str, scope: str) -> str:
        return self.token_response(base_url, jwt, scope).access_token
