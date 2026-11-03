"""Okta REST client pooling and endpoint routing."""

import fnmatch

from dlt.sources.helpers.rest_client.client import RESTClient

from .telemetry import NullTelemetryRecorder, Telemetry
from .utils.http import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
)

API_RATE_LIMIT_ENDPOINTS = [
    # Dedicated family for per-user factor enumeration: it must precede the
    # broader /api/v1/users* pattern so the potentially large volume of factor
    # requests cannot queue-starve or rate-limit-clamp the users listing,
    # which Okta serves from a different rate-limit bucket.
    "/api/v1/users/*/factors",
    "/api/v1/users*",
    "/api/v1/groups*",
    "/api/v1/apps*",
    "/api/v1/idps*",
    "/api/v1/iam*",
    "/api/v1/devices*",
    "/oauth2/v1/clients*",
    "*",
]


class ClientPool:
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
        # Keep rate-limit arguments compatible with source config; DLT handles retries.
        self._clients: dict[str, RESTClient] = {
            pattern: RESTClient(
                base_url=base_url,
                headers={"accept": "application/json"},
                auth=auth,
                paginator=paginator,
            )
            for pattern in API_RATE_LIMIT_ENDPOINTS
        }
        self._saml_metadata_client = RESTClient(
            base_url=base_url,
            headers={"accept": "application/xml"},
            auth=auth,
            paginator=paginator,
        )
        self._idp_saml_metadata_client = RESTClient(
            base_url=base_url,
            headers={"accept": "application/xml"},
            auth=auth,
            paginator=paginator,
        )

    def get_client(self, path: str) -> RESTClient:
        for pattern in self._clients:
            if fnmatch.fnmatch(path, pattern):
                return self._clients[pattern]
        return self._clients["*"]

    def paginate(self, path: str, **kwargs):
        for page in self.get_client(path).paginate(path, **kwargs):
            try:
                row_count = len(page)
            except TypeError:
                row_count = None
            self._telemetry.record_page(path, row_count)
            yield page

    def get(self, path: str, **kwargs):
        return self.get_client(path).get(path, **kwargs)

    def get_saml_metadata(self, path: str):
        if fnmatch.fnmatch(path, "/api/v1/idps*"):
            return self._idp_saml_metadata_client.get(path)
        return self._saml_metadata_client.get(path)
