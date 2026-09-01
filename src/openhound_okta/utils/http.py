import logging
import random
import re
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from threading import BoundedSemaphore, Lock
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

import requests
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.requests.retry import (
    DEFAULT_RETRY_EXCEPTIONS,
    DEFAULT_RETRY_STATUS,
)
from dlt.sources.helpers.requests.session import Session

from .auth import (
    OktaBearerAuth,
    UnauthorizedClassification,
    UnauthorizedDecision,
)

logger = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = set(DEFAULT_RETRY_STATUS)
RETRYABLE_REQUEST_EXCEPTIONS = DEFAULT_RETRY_EXCEPTIONS
DEFAULT_ENDPOINT_CONCURRENCY = 2
DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS = 900.0
DEFAULT_RATE_LIMIT_REMAINING_RESERVE = 1
DEFAULT_MAX_COOLDOWN_SECONDS = 300.0
RATE_LIMIT_PROBE_INTERVAL_SECONDS = 1.0


@dataclass
class OktaRetryContext:
    endpoint_family: str
    url: str
    status_code: int | None
    attempts: int
    elapsed_seconds: float = 0.0
    app_id: str | None = None
    cursor: str | None = None


@dataclass
class InitialReadTimeoutBudget:
    max_attempts: int
    consumed: bool = False

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")


class OktaRetryExhaustedError(RuntimeError):
    def __init__(self, context: OktaRetryContext):
        self.context = context
        detail = (
            f"Okta request retries exhausted for endpoint_family={context.endpoint_family} "
            f"status={context.status_code} attempts={context.attempts} "
            f"elapsed={context.elapsed_seconds:.2f}s url={context.url}"
        )
        if context.app_id:
            detail += f" app_id={context.app_id}"
        if context.cursor:
            detail += f" cursor={context.cursor}"
        super().__init__(detail)


class EndpointThrottle:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        max_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
        remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
        max_cooldown_seconds: float = DEFAULT_MAX_COOLDOWN_SECONDS,
    ):
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if remaining_reserve < 0:
            raise ValueError("remaining_reserve cannot be negative")
        if max_cooldown_seconds <= 0:
            raise ValueError("max_cooldown_seconds must be positive")
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self._lock = Lock()
        self._semaphore = BoundedSemaphore(max_concurrency)
        self._remaining_reserve = remaining_reserve
        self._max_cooldown_seconds = max_cooldown_seconds
        self._next_allowed_at = 0.0
        self._request_interval = 0.0
        self._observed_reset_at: float | None = None
        self._observed_remaining: int | None = None

    def acquire(self) -> None:
        self._semaphore.acquire()
        try:
            self.wait()
        except BaseException:
            self._semaphore.release()
            raise

    def release(self) -> None:
        self._semaphore.release()

    def wait(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                delay = self._next_allowed_at - now
                if delay <= 0:
                    self._next_allowed_at = now + self._request_interval
                    return
            self._sleep(delay)

    def defer(self, delay: float, *, minimum_interval: float = 0.0) -> float:
        if delay <= 0:
            return 0.0
        delay = min(delay, self._max_cooldown_seconds)
        with self._lock:
            self._next_allowed_at = max(
                self._next_allowed_at,
                self._clock() + delay,
            )
            self._request_interval = max(
                self._request_interval,
                minimum_interval,
            )
        return delay

    def observe_response(self, response: requests.Response) -> None:
        remaining_header = response.headers.get("X-Rate-Limit-Remaining")
        reset_header = response.headers.get("X-Rate-Limit-Reset")
        if remaining_header is None or reset_header is None:
            return

        try:
            remaining = int(remaining_header.strip())
            reset_at = float(reset_header.strip())
        except ValueError:
            logger.debug(
                "Ignoring invalid Okta rate limit headers remaining=%r reset=%r",
                remaining_header,
                reset_header,
            )
            return

        with self._lock:
            if self._observed_reset_at is None or reset_at > self._observed_reset_at:
                self._observed_reset_at = reset_at
                self._observed_remaining = remaining
            elif reset_at == self._observed_reset_at:
                self._observed_remaining = min(
                    remaining,
                    self._observed_remaining
                    if self._observed_remaining is not None
                    else remaining,
                )
            else:
                return

            remaining = self._observed_remaining
            window_seconds = min(
                max(self._observed_reset_at - self._wall_clock(), 0.0),
                self._max_cooldown_seconds,
            )
            now = self._clock()
            if remaining <= self._remaining_reserve:
                cooldown = min(
                    max(window_seconds + 1.0, 1.0),
                    self._max_cooldown_seconds,
                )
                self._next_allowed_at = max(
                    self._next_allowed_at,
                    now + cooldown,
                )
                self._request_interval = max(
                    self._request_interval,
                    RATE_LIMIT_PROBE_INTERVAL_SECONDS,
                )
                return

            usable_requests = remaining - self._remaining_reserve
            self._request_interval = window_seconds / usable_requests
            self._next_allowed_at = max(
                self._next_allowed_at,
                now + self._request_interval,
            )


class OktaRESTClient(RESTClient):
    def __init__(
        self,
        *args: Any,
        endpoint_family: str,
        throttle: EndpointThrottle,
        max_attempts: int | None = None,
        rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
        max_retry_delay_seconds: float | None = None,
        clock: Callable[[], float] = time.time,
        elapsed_clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
        **kwargs: Any,
    ):
        kwargs.setdefault("session", Session(raise_for_status=False))
        super().__init__(*args, **kwargs)
        if rate_limit_max_elapsed_seconds <= 0:
            raise ValueError("rate_limit_max_elapsed_seconds must be positive")
        self.endpoint_family = endpoint_family
        self._throttle = throttle
        self._max_attempts = (
            max_attempts
            if max_attempts is not None
            else self._config.request_max_attempts
        )
        self._rate_limit_max_elapsed_seconds = rate_limit_max_elapsed_seconds
        self._max_retry_delay_seconds = (
            max_retry_delay_seconds
            if max_retry_delay_seconds is not None
            else self._config.request_max_retry_delay
        )
        if self._max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self._max_retry_delay_seconds <= 0:
            raise ValueError("max_retry_delay_seconds must be positive")
        self._backoff_factor = self._config.request_backoff_factor
        self._clock = clock
        self._elapsed_clock = elapsed_clock
        self._sleep = sleep
        self._jitter = jitter

    def _send_once(self, request: requests.Request, **kwargs: Any) -> requests.Response:
        return super()._send_request(request, **kwargs)

    def _send_request(
        self, request: requests.Request, **kwargs: Any
    ) -> requests.Response:
        initial_read_timeout_budget = kwargs.pop(
            "initial_read_timeout_budget",
            None,
        )
        read_timeout_max_attempts = self._max_attempts
        if (
            initial_read_timeout_budget is not None
            and not initial_read_timeout_budget.consumed
        ):
            read_timeout_max_attempts = min(
                initial_read_timeout_budget.max_attempts,
                self._max_attempts,
            )

        started_at = self._elapsed_clock()
        attempt = 0
        rate_limit_attempt = 0
        transient_attempt = 0
        read_timeout_attempt = 0
        unauthorized_retry_attempted = False
        while True:
            attempt += 1
            self._throttle.acquire()
            try:
                response = self._send_once(request, **kwargs)
                response.raise_for_status()
                self._throttle.observe_response(response)
                self._throttle.release()
                if initial_read_timeout_budget is not None:
                    initial_read_timeout_budget.consumed = True
                return response
            except requests.HTTPError as exc:
                response = exc.response
                status_code = response.status_code if response is not None else None
                unauthorized_decision = None
                if status_code == 401 and not unauthorized_retry_attempted:
                    unauthorized_decision = self._retry_after_unauthorized(
                        request,
                        response,
                    )
                if (
                    unauthorized_decision is not None
                    and unauthorized_decision.retry
                ):
                    unauthorized_retry_attempted = True
                    self._throttle.release()
                    continue
                if status_code not in RETRYABLE_STATUS_CODES:
                    self._throttle.release()
                    raise
                if status_code == 429:
                    rate_limit_attempt += 1
                    retry_attempt = rate_limit_attempt
                else:
                    transient_attempt += 1
                    retry_attempt = transient_attempt
                try:
                    delay = self._retry_delay(response, retry_attempt)
                    context = self._retry_context(
                        response,
                        status_code,
                        attempt,
                        started_at,
                        request,
                    )
                except BaseException:
                    self._throttle.release()
                    raise
                if status_code == 429:
                    delay = self._throttle.defer(
                        delay,
                        minimum_interval=RATE_LIMIT_PROBE_INTERVAL_SECONDS,
                    )
                    self._throttle.release()
                    if (
                        context.elapsed_seconds + delay
                        >= self._rate_limit_max_elapsed_seconds
                    ):
                        raise OktaRetryExhaustedError(context) from exc
                else:
                    self._throttle.release()
                    if transient_attempt >= self._max_attempts:
                        raise OktaRetryExhaustedError(context) from exc
                logger.warning(
                    "Retrying Okta request after status=%s endpoint_family=%s "
                    "attempt=%s rate_limit_attempt=%s transient_attempt=%s/%s "
                    "elapsed=%.2fs "
                    "delay=%.2fs url=%s app_id=%s cursor=%s",
                    status_code,
                    self.endpoint_family,
                    attempt,
                    rate_limit_attempt,
                    transient_attempt,
                    self._max_attempts,
                    context.elapsed_seconds,
                    delay,
                    context.url,
                    context.app_id,
                    context.cursor,
                )
                if status_code != 429:
                    self._sleep(delay)
            except RETRYABLE_REQUEST_EXCEPTIONS as exc:
                self._throttle.release()
                transient_attempt += 1
                is_read_timeout = isinstance(exc, requests.exceptions.ReadTimeout)
                if is_read_timeout:
                    read_timeout_attempt += 1
                context = self._retry_context(
                    None,
                    None,
                    attempt,
                    started_at,
                    request,
                )
                transient_max_attempts = (
                    read_timeout_max_attempts
                    if is_read_timeout
                    else self._max_attempts
                )
                exhausted = (
                    read_timeout_attempt >= read_timeout_max_attempts
                    if is_read_timeout
                    else transient_attempt >= self._max_attempts
                )
                if exhausted:
                    raise OktaRetryExhaustedError(context) from exc
                delay = self._retry_delay(None, transient_attempt)
                logger.warning(
                    "Retrying Okta request after transient error=%s "
                    "endpoint_family=%s attempt=%s transient_attempt=%s/%s "
                    "elapsed=%.2fs delay=%.2fs url=%s app_id=%s cursor=%s",
                    exc.__class__.__name__,
                    self.endpoint_family,
                    attempt,
                    transient_attempt,
                    transient_max_attempts,
                    context.elapsed_seconds,
                    delay,
                    context.url,
                    context.app_id,
                    context.cursor,
                )
                self._sleep(delay)
            except BaseException:
                self._throttle.release()
                raise

    def _retry_after_unauthorized(
        self,
        request: requests.Request,
        response: requests.Response | None,
    ) -> UnauthorizedDecision | None:
        auth = self._refreshable_auth(request)
        if auth is None or response is None:
            return None

        failed_access_token = self._response_bearer_token(response)
        if failed_access_token is None:
            return None

        classification = self._classify_unauthorized(response)
        decision = auth.handle_unauthorized(failed_access_token, classification)
        logger.warning(
            "Handled Okta bearer 401 endpoint_family=%s classification=%s "
            "reason=%s invalidated=%s retry=%s url=%s",
            self.endpoint_family,
            classification.value,
            decision.reason,
            decision.invalidated,
            decision.retry,
            response.url,
        )
        return decision

    def _refreshable_auth(self, request: requests.Request) -> OktaBearerAuth | None:
        request_auth = getattr(request, "auth", None)
        auth = request_auth if request_auth is not None else self.auth
        return auth if isinstance(auth, OktaBearerAuth) else None

    @staticmethod
    def _response_bearer_token(response: requests.Response) -> str | None:
        prepared_request = getattr(response, "request", None)
        headers = getattr(prepared_request, "headers", None)
        if headers is None:
            return None

        authorization = headers.get("Authorization")
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None

        access_token = authorization.removeprefix("Bearer ")
        return access_token or None

    @staticmethod
    def _classify_unauthorized(
        response: requests.Response,
    ) -> UnauthorizedClassification:
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

    def _retry_context(
        self,
        response: requests.Response | None,
        status_code: int | None,
        attempts: int,
        started_at: float,
        request: requests.Request | None = None,
    ) -> OktaRetryContext:
        url = response.url if response is not None else getattr(request, "url", "")
        parsed = urlparse(url)
        app_match = re.search(r"/api/v1/apps/([^/]+)/users", parsed.path)
        cursor = parse_qs(parsed.query).get("after", [None])[0]
        return OktaRetryContext(
            endpoint_family=self.endpoint_family,
            url=url,
            status_code=status_code,
            attempts=attempts,
            elapsed_seconds=max(self._elapsed_clock() - started_at, 0.0),
            app_id=app_match.group(1) if app_match else None,
            cursor=cursor,
        )

    def _retry_delay(self, response: requests.Response | None, attempt: int) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                parsed = _parse_retry_after(retry_after, self._clock)
                if parsed is not None:
                    return self._clamp_retry_delay(parsed + self._jitter())
            reset = response.headers.get("X-Rate-Limit-Reset")
            if reset and reset.strip().isdigit():
                delay = max(float(reset) - self._clock() + 1.0, 1.0)
                return self._clamp_retry_delay(delay + self._jitter())
        base_delay = self._backoff_factor * (2 ** (attempt - 1))
        return self._clamp_retry_delay(base_delay + self._jitter())

    def _clamp_retry_delay(self, delay: float) -> float:
        return max(min(delay, self._max_retry_delay_seconds), 0.0)


def _parse_retry_after(
    retry_after: str,
    clock: Callable[[], float] = time.time,
) -> float | None:
    if retry_after.strip().isdigit():
        return max(float(retry_after), 1.0)
    try:
        retry_at = parsedate_to_datetime(retry_after)
    except (TypeError, ValueError):
        return None
    return max(retry_at.timestamp() - clock(), 1.0)
