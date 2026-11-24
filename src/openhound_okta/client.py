"""Custom Okta client pool and endpoint-family routing."""

import fnmatch
from typing import Callable, Final

from dlt.sources.helpers.rest_client.client import RESTClient

from .telemetry import NullTelemetryRecorder, Telemetry
from .utils.http import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    DEFAULT_ORG_CONCURRENCY,
    DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
    EndpointThrottle,
    OktaRESTClient,
    OrgThrottle,
)

# One entry per Okta rate limit bucket the collector touches. Each family's
# EndpointThrottle paces itself from the X-Rate-Limit-* headers of its own
# responses, so a family must map to exactly one Okta bucket: two families on
# one bucket overshoot it, and one family across two buckets paces both from
# whichever headers arrived last. First fnmatch match wins and fnmatch's "*"
# matches "/" too, so narrower patterns precede broader ones. The per-minute
# values are what one org's Rate Limit Buckets table reported; they vary by
# org tier and are documentation only, the throttle never hard-codes them.
# An OAuth app is allocated 50% of each bucket by default, so the collector
# typically sees half of every value quoted here.
API_RATE_LIMIT_ENDPOINTS = [
    # Bucket /api/v1/users/{id:.+} READ (2000/min): every GET below /users/<id>,
    # that is factors, roles and role targets. The greedy {id:.+} template is
    # what separates these from the listing. The literal "/users/" keeps
    # "/api/v1/users" and "/api/v1/users?limit=..." out of this family.
    "/api/v1/users/*",
    # Bucket /api/v1/users (600/min): the users listing.
    "/api/v1/users*",
    # Bucket /api/v1/groups (500/min): listing, /groups/{id}/users, roles and
    # role targets. GET /api/v1/groups/{id} has its own bucket (1000/min) but
    # fnmatch cannot express "exactly one more segment"; it is folded in here
    # on purpose (one call per group push mapping, and pacing against the
    # smaller budget is the safe error).
    "/api/v1/groups*",
    # Bucket /api/v1/apps (100/min): the listing and every per-app sub-resource
    # (users, groups, grants, group push mappings, credentials, SAML metadata).
    # GET /api/v1/apps/{id} has its own bucket (500/min) but is never called;
    # {id} matches one segment, so /apps/{id}/users lands here (confirmed).
    "/api/v1/apps*",
    # Bucket /api/v1/iam (1600/min): roles, resource sets, assignees.
    "/api/v1/iam*",
    # Bucket /api/v1/devices (100/min): the devices listing.
    "/api/v1/devices*",
    # Bucket /oauth2/v1/clients (100/min): listing, roles and role targets.
    "/oauth2/v1/clients*",
    # API service integrations have their own bucket (100/min), undocumented
    # and absent from the Rate Limit Buckets table: api-services and their
    # secrets.
    "/integrations/*",
    # Bucket /api/v1 (1000/min): the catch-all for org, policies and their
    # mappings, realms, idps (listing, metadata.xml, users), authorization
    # servers, agent pools and API tokens. There is no idps bucket.
    "*",
]

# Families whose endpoints also serve SAML metadata as XML.
SAML_METADATA_FAMILIES: Final = ("/api/v1/apps*", "*")


class ClientPool:
    """REST clients for the Okta org, one per endpoint family.

    Each family has its own EndpointThrottle pacing requests from the rate limit
    headers of its own Okta bucket; all throttles share one org-wide in-flight
    gate. A request is routed to its family by matching the path against
    API_RATE_LIMIT_ENDPOINTS.
    """

    def __init__(
        self,
        base_url: str,
        auth,
        paginator,
        throttle_factory: Callable[..., EndpointThrottle] = EndpointThrottle,
        endpoint_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
        org_concurrency: int = DEFAULT_ORG_CONCURRENCY,
        rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
        rate_limit_remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
        telemetry: Telemetry | None = None,
    ):
        """Create the throttles and clients for every endpoint family.

        Args:
            base_url: Okta org base URL.
            auth: requests auth applied to every request.
            paginator: dlt paginator following Link headers.
            throttle_factory: Builds a throttle per family; tests substitute fakes.
            endpoint_concurrency: Maximum in-flight requests per family.
            org_concurrency: Maximum in-flight requests across all families.
            rate_limit_max_elapsed_seconds: Retry budget for a request stuck on 429.
            rate_limit_remaining_reserve: Requests kept as headroom in each window.
            telemetry: Collection telemetry recorder, or None to disable.
        """
        self._telemetry = telemetry or NullTelemetryRecorder()
        # One org throttle per source, shared by every endpoint family's
        # throttle: the in-flight permit gate and the org-wide outage backoff.
        org_throttle = OrgThrottle(org_concurrency)
        throttles = {
            pattern: throttle_factory(
                max_concurrency=endpoint_concurrency,
                remaining_reserve=rate_limit_remaining_reserve,
                org_throttle=org_throttle,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        self._clients: dict[str, RESTClient] = {
            pattern: OktaRESTClient(
                base_url=base_url,
                headers={"accept": "application/json"},
                auth=auth,
                paginator=paginator,
                endpoint_family=pattern,
                throttle=throttles[pattern],
                rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
                telemetry=self._telemetry,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        # SAML metadata is XML; one client per family that serves it, sharing
        # that family's throttle.
        self._saml_metadata_clients: dict[str, RESTClient] = {
            pattern: OktaRESTClient(
                base_url=base_url,
                headers={"accept": "application/xml"},
                auth=auth,
                paginator=paginator,
                endpoint_family=pattern,
                throttle=throttles[pattern],
                rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
                telemetry=self._telemetry,
            )
            for pattern in SAML_METADATA_FAMILIES
        }

    @staticmethod
    def _endpoint_family(path: str) -> str:
        """Map a request path to its endpoint family pattern.

        Args:
            path: Request path, possibly with a query string.

        Returns:
            The first matching pattern in API_RATE_LIMIT_ENDPOINTS, else "*".
        """
        for pattern in API_RATE_LIMIT_ENDPOINTS:
            if fnmatch.fnmatch(path, pattern):
                return pattern
        return "*"

    def get_client(self, path: str) -> RESTClient:
        """Return the JSON client for the path's endpoint family.

        Args:
            path: Request path.
        """
        return self._clients[self._endpoint_family(path)]

    def paginate(self, path: str, **kwargs):
        """Paginate a path through its family's client, recording pages in telemetry.

        Args:
            path: Request path.
            **kwargs: Passed to the client's paginate, such as params or data_selector.

        Yields:
            Each page of items.
        """
        for page in self.get_client(path).paginate(path, **kwargs):
            try:
                row_count = len(page)
            except TypeError:
                row_count = None
            self._telemetry.record_page(path, row_count)
            yield page

    def get(self, path: str, **kwargs):
        """Issue a single GET through the path's family client.

        Args:
            path: Request path.
            **kwargs: Passed to the client's get.

        Returns:
            The response.
        """
        return self.get_client(path).get(path, **kwargs)

    def get_saml_metadata(self, path: str):
        """Fetch SAML metadata XML through the path's family client.

        Args:
            path: Metadata path of an application or identity provider.

        Returns:
            The response with XML content.
        """
        return self._saml_metadata_clients[self._endpoint_family(path)].get(path)
