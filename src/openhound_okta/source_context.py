"""Shared Okta collection context and settings."""

from dataclasses import dataclass, field
from threading import Lock
from typing import Final
from urllib.parse import urlparse

from .client import ClientPool
from .telemetry import NullTelemetryRecorder, Telemetry

APPLICATION_GRANTS_ACCESS_DENIED_LIMIT: Final[int] = 10
"""Consecutive access-denied (403) responses after which application OAuth 2.0
grant collection is abandoned for all remaining applications."""

APPLICATION_USERS_PAGE_SIZE = 500
GROUPS_PAGE_SIZE = 200
GROUPS_PAGE_SIZE_FALLBACK_DIVISORS = (1, 2, 4)
APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE = 20
APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE = 200
GROUP_PUSH_MAPPINGS_PAGE_SIZE = 1000
IDENTITY_PROVIDER_USERS_PAGE_SIZE = 200


class ConsecutiveAccessDeniedBreaker:
    """Trips after an uninterrupted run of access-denied (403) responses.

    Least-privilege collector roles cannot read some per-object endpoints at
    all, so once every request in a row is denied there is no point in issuing
    one request per remaining object. Only a successful request disproves the
    missing permission and resets the run, so callers must not record outcomes
    that carry no permission signal (such as a 404 for a deleted object);
    those neither count nor reset. Once tripped, the breaker never resets.
    The breaker is thread-safe.

    Attributes:
        tripped: Whether the denial limit has been reached and callers should
            stop issuing further requests.
    """

    def __init__(self, limit: int) -> None:
        """Create a breaker that trips at the given denial limit.

        Args:
            limit: Number of consecutive access-denied responses that trips
                the breaker. Must be at least 1.

        Raises:
            ValueError: If limit is less than 1.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        self._limit: int = limit
        self._lock: Lock = Lock()
        self._consecutive_denials: int = 0
        self._tripped: bool = False

    @property
    def tripped(self) -> bool:
        """Whether the breaker has tripped and requests should stop.

        Returns:
            True once record_access_denied has counted the limit of
            consecutive denials, False otherwise.
        """
        with self._lock:
            return self._tripped

    def record_success(self) -> None:
        """Reset the consecutive denial count after a successful request."""
        with self._lock:
            self._consecutive_denials = 0

    def record_access_denied(self) -> bool:
        """Count one access-denied response toward the limit.

        Returns:
            True when this denial is the one that trips the breaker, False
            when the breaker was already tripped or the limit has not been
            reached yet.
        """
        with self._lock:
            if self._tripped:
                return False
            self._consecutive_denials += 1
            if self._consecutive_denials >= self._limit:
                self._tripped = True
                return True
            return False


@dataclass
class SourceContext:
    """Context for Okta API operations.

    Attributes:
        pool: Client pool used to issue Okta API requests.
        tenant_domain: Casefolded hostname of the collected Okta tenant.
        telemetry: Collection-phase telemetry recorder.
        application_grants_breaker: Shared breaker that stops application
            OAuth 2.0 grant collection after consecutive access-denied
            responses.
        application_users_page_size: Users requested per application-users
            page.
        groups_page_size: Groups requested per expanded groups page.
        application_group_assignments_page_size: Groups requested per
            application page.
        group_push_mappings_page_size: Mappings requested per group-push page.
        identity_provider_users_page_size: Users requested per
            identity-provider page.
    """

    pool: ClientPool
    tenant_domain: str
    telemetry: Telemetry = field(default_factory=NullTelemetryRecorder)
    application_grants_breaker: ConsecutiveAccessDeniedBreaker = field(
        default_factory=lambda: ConsecutiveAccessDeniedBreaker(
            APPLICATION_GRANTS_ACCESS_DENIED_LIMIT
        )
    )
    application_users_page_size: int = APPLICATION_USERS_PAGE_SIZE
    groups_page_size: int = GROUPS_PAGE_SIZE
    application_group_assignments_page_size: int = (
        APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    )
    group_push_mappings_page_size: int = GROUP_PUSH_MAPPINGS_PAGE_SIZE
    identity_provider_users_page_size: int = IDENTITY_PROVIDER_USERS_PAGE_SIZE


def _tenant_domain_from_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("Okta base URL is unavailable during collection")
    try:
        parsed = urlparse(base_url.strip())
        _ = parsed.port
        tenant_domain = parsed.hostname
    except ValueError as error:
        raise ValueError(
            "Okta base URL must include a URL scheme and hostname"
        ) from error
    if not parsed.scheme or not tenant_domain:
        raise ValueError("Okta base URL must include a URL scheme and hostname")
    return tenant_domain.casefold()
