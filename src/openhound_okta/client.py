"""Native DLT client with Okta retry headers and collection telemetry."""

import logging
from email.utils import parsedate_to_datetime
from functools import wraps
from math import ceil
from typing import Any
from urllib.parse import urlsplit

from requests import PreparedRequest, Response
from dlt.common.configuration import resolve_configuration
from dlt.common.configuration.specs import RuntimeConfiguration
from dlt.sources.helpers.requests import Client as RequestsClient
from dlt.sources.helpers.requests.session import Session
from dlt.sources.helpers.rest_client.client import RESTClient

from .telemetry import NullTelemetryRecorder, Telemetry
from .utils.http import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
)

logger = logging.getLogger(__name__)


def _rate_limit_reset(response: Response) -> tuple[int, float] | None:
    """Read the reset timestamp and buffered delay using Okta's server time."""
    try:
        server_date = parsedate_to_datetime(response.headers["Date"])
        reset = int(response.headers["X-Rate-Limit-Reset"])
        delay = reset - server_date.timestamp()
        if delay >= 0:
            return reset, delay + 1
    except (KeyError, TypeError, ValueError, OverflowError):
        pass
    return None


def okta_retry_after(response: Response, *args: Any, **kwargs: Any) -> Response:
    """Expose a timed Okta 429 reset as Retry-After for DLT's retry handler."""
    headers = response.headers
    if response.status_code != 429:
        return response
    # Zero limit and remaining indicate concurrency, not a timed budget.
    concurrent_limit = (
        headers.get("X-Rate-Limit-Limit") == "0"
        and headers.get("X-Rate-Limit-Remaining") == "0"
    )
    if "Retry-After" not in headers and not concurrent_limit:
        reset = _rate_limit_reset(response)
        if reset is not None:
            headers["Retry-After"] = str(ceil(reset[1]))
    logger.info(
        "Okta API rate limit reached path=%s limit=%s remaining=%s "
        "reset_at=%s retry_after=%s",
        urlsplit(response.url or "").path,
        headers.get("X-Rate-Limit-Limit"),
        headers.get("X-Rate-Limit-Remaining"),
        headers.get("X-Rate-Limit-Reset"),
        headers.get("Retry-After"),
    )
    return response


def okta_http_session() -> Session:
    """Configure native DLT retries and normalize Okta's timed rate-limit headers."""
    config = resolve_configuration(RuntimeConfiguration()).copy()
    # DLT also caps Retry-After; allow a full Okta window plus the buffer.
    config.request_max_retry_delay = max(config.request_max_retry_delay, 61)
    http_client = RequestsClient(raise_for_status=False)
    http_client.update_from_config(config)
    session = http_client.session
    send = session.send

    @wraps(send)
    def send_with_okta_retry_after(request: PreparedRequest, **kwargs: Any) -> Response:
        """Normalize rate limits before request-specific response handlers run."""
        # Pagination replaces session hooks; inject into each prepared request.
        request.hooks = {
            **request.hooks,
            "response": [
                okta_retry_after,
                *[
                    hook
                    for hook in request.hooks.get("response", [])
                    if hook is not okta_retry_after
                ],
            ],
        }
        return send(request, **kwargs)

    session.send = send_with_okta_retry_after  # type: ignore[method-assign]
    return session


class ClientPool:
    """Use one native DLT client with Okta header-based retries."""

    def __init__(
        self,
        base_url: str,
        auth,
        paginator,
        endpoint_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
        rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
        rate_limit_remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
        telemetry: Telemetry | None = None,
    ):
        self._telemetry = telemetry or NullTelemetryRecorder()
        self.client = RESTClient(
            base_url=base_url,
            headers={"accept": "application/json"},
            auth=auth,
            paginator=paginator,
            session=okta_http_session(),
        )

    def paginate(self, path: str, **kwargs):
        """Yield DLT pages and record their row counts."""
        for page in self.client.paginate(path, **kwargs):
            try:
                row_count = len(page)
            except TypeError:
                row_count = None
            self._telemetry.record_page(path, row_count)
            yield page
