"""HTTP integration tests against an in-process, sample-backed Okta API."""

import json
import re
from collections.abc import Iterator
from copy import deepcopy
from dataclasses import dataclass
from math import ceil
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import httpx2
import pytest
import requests
from dlt.sources.helpers.rest_client.client import RESTClient
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.testclient import TestClient
from openhound_okta.source import ClientPool, OktaTokenCredentials, _request_auth
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

TEST_DATA_DIR = Path(__file__).parent / "test_data" / "api"
DEFAULT_PAGE_SIZE = 2
PageLimit = Annotated[int, Query(ge=1)]

# Rate-limit scenarios opt in to these counts; child counts apply per parent.
DEFAULT_PAGE_COUNTS: dict[str, int] = {
    r"/api/v1/users": 350,
    r"/api/v1/groups": 275,
    r"/api/v1/apps": 60,
    r"/api/v1/devices": 60,
    r"/api/v1/iam/roles": 20,
    r"/api/v1/iam/resource-sets": 10,
    r"/api/v1/groups/[^/]+/users": 5,
    r"/api/v1/apps/[^/]+/users": 10,
}

# First match wins: exact/subresource rules precede their broader families.
RATE_LIMIT_RULES: dict[str, int] = {
    r"/api/v1/users.*": 300,
    r"/api/v1/groups/[^/]+": 500,
    r"/api/v1/groups.*": 250,
    r"/api/v1/apps.*": 50,
    r"/api/v1/devices.*": 50,
    r"/api/v1/iam.*": 800,
    r"/api/v1.*": 500,
    r"/oauth2/v1/clients.*": 50,
    r"/oauth2/v1.*": 1000,
}


@dataclass
class RateLimitBucket:
    """One application-specific request budget for a fixed 60-second window."""

    limit: int
    used: int = 0
    reset_at: float = 0


class RateLimitState:
    """Per-test bucket counters and a clock advanced explicitly instead of sleeping."""

    def __init__(self) -> None:
        """Start with the supplied application limits and a fixed epoch timestamp."""
        self.now: float = 1_700_000_000
        self.buckets: dict[str, RateLimitBucket] = {
            pattern: RateLimitBucket(limit)
            for pattern, limit in RATE_LIMIT_RULES.items()
        }

    def consume(self, request: Request) -> tuple[bool, dict[str, str]]:
        """Charge only the winning bucket and snapshot its response headers."""
        path = request.url.path
        for pattern, bucket in self.buckets.items():
            if not re.fullmatch(pattern, path):
                continue
            if self.now >= bucket.reset_at:
                bucket.used = 0
                bucket.reset_at = self.now + 60
            allowed = bucket.used < bucket.limit
            if allowed:
                bucket.used += 1
            headers = {
                "X-Rate-Limit-Limit": str(bucket.limit),
                "X-Rate-Limit-Remaining": str(max(0, bucket.limit - bucket.used)),
                "X-Rate-Limit-Reset": str(ceil(bucket.reset_at)),
            }
            if not allowed:
                headers["Retry-After"] = str(ceil(bucket.reset_at - self.now))
            return allowed, headers
        return True, {}


def load_json(filename: str) -> dict[str, Any] | list[Any]:
    """Load a fresh copy of a sample API response."""
    with (TEST_DATA_DIR / filename).open(encoding="utf-8") as file:
        return json.load(file)


def page_count(request: Request) -> int | None:
    """Find the first configured page count for an endpoint path."""
    for pattern, count in request.app.state.page_counts.items():
        if re.fullmatch(pattern, request.url.path):
            if count < 0:
                raise HTTPException(
                    status_code=400, detail="Page count must be nonnegative"
                )
            return count
    return None


def synthetic_page(
    request: Request,
    data: list[dict[str, Any]] | dict[str, Any],
    *,
    limit: int,
    after: int,
    key: str | None = None,
) -> Any:
    """Generate only the requested sample-backed page, preserving response envelopes."""
    count = page_count(request)
    if count is None:
        return data
    if after >= max(count, 1):
        raise HTTPException(status_code=400, detail="Invalid pagination parameters")

    samples = data[key] if key else data
    rows = []
    if count and samples:
        for index in range(limit):
            row = deepcopy(samples[index % len(samples)])
            if "id" in row:
                row["id"] = f"{row['id']}_synthetic_{after}_{index}"
            rows.append(row)
    content = {**data, key: rows} if key else rows
    headers = {}
    if rows and after + 1 < count:
        next_url = request.url.include_query_params(after=after + 1, limit=limit)
        headers["Link"] = f'<{next_url}>; rel="next"'
    return JSONResponse(content=content, headers=headers)


@pytest.fixture
def mock_okta_api() -> FastAPI:
    """Build an isolated mock API and record requests for each test."""
    app = FastAPI()
    app.state.requests = []
    app.state.rate_limits = RateLimitState()
    app.state.page_counts = {}

    @app.middleware("http")
    async def record_request(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Record requests and enforce the most-specific matching rate-limit bucket."""
        app.state.requests.append(
            {
                "path": request.url.path,
                "query": dict(request.query_params),
                "authorization": request.headers.get("authorization"),
                "accept": request.headers.get("accept"),
            }
        )
        # No await between checking and consuming: concurrent ASGI requests cannot
        # interleave counter updates on the TestClient event loop.
        allowed, headers = app.state.rate_limits.consume(request)
        if not allowed:
            return JSONResponse(
                status_code=429,
                headers=headers,
                content={
                    "errorCode": "E0000047",
                    "errorSummary": "API call exceeded rate limit due to too many requests.",
                    "errorLink": "E0000047",
                    "errorId": "test-rate-limit",
                    "errorCauses": [],
                },
            )
        response = await call_next(request)
        response.headers.update(headers)
        return response

    @app.exception_handler(404)
    async def not_found(
        request: Request, error: StarletteHTTPException
    ) -> JSONResponse:
        """Return an Okta-shaped error for unknown paths."""
        return JSONResponse(
            status_code=404,
            content={
                "errorCode": "E0000007",
                "errorSummary": "Not found: Resource not found",
                "errorLink": "E0000007",
                "errorId": "test-error",
                "errorCauses": [],
            },
        )

    @app.get("/api/v1/org")
    async def organization() -> Any:
        """Return organization metadata as an object."""
        return load_json("organization.json")

    @app.get("/api/v1/users")
    async def users(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return sample users."""
        return synthetic_page(
            request, load_json("users.json"), limit=limit, after=after
        )

    @app.get("/api/v1/groups")
    async def groups(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return sample groups; expanded stats will be added with fixture repair."""
        return synthetic_page(
            request, load_json("groups.json"), limit=limit, after=after
        )

    @app.get("/api/v1/groups/{group_id}")
    async def group(group_id: str) -> Any:
        """Return a sample group with the requested ID."""
        return {**load_json("groups.json")[0], "id": group_id}

    @app.get("/api/v1/groups/{group_id}/users")
    async def group_users(
        group_id: str,
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return sample members for any group ID."""
        return synthetic_page(
            request, load_json("group_members.json"), limit=limit, after=after
        )

    @app.get("/api/v1/apps")
    async def applications(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return sample applications."""
        return synthetic_page(
            request, load_json("applications.json"), limit=limit, after=after
        )

    @app.get("/api/v1/apps/{app_id}/users")
    async def application_users(
        app_id: str,
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return sample assigned users for any application ID."""
        return synthetic_page(
            request, load_json("application_users.json"), limit=limit, after=after
        )

    @app.get("/api/v1/apps/{app_id}/credentials/jwks")
    async def application_jwks(app_id: str) -> Any:
        """Expose sample keys as the array documented by the Okta endpoint."""
        return load_json("app_jwks.json")["jwks"]["keys"]

    @app.get("/api/v1/apps/{app_id}/credentials/secrets")
    async def application_secrets(app_id: str) -> Any:
        """Return sample client-secret metadata for any application ID."""
        return load_json("client_secrets.json")

    @app.get("/api/v1/iam/roles")
    async def custom_roles(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Keep the roles response envelope intact."""
        return synthetic_page(
            request,
            load_json("custom_roles.json"),
            limit=limit,
            after=after,
            key="roles",
        )

    @app.get("/api/v1/iam/roles/{role_id}/permissions")
    async def custom_role_permissions(role_id: str) -> Any:
        """Return sample permissions for any role ID."""
        return load_json("custom_role_permissions.json")

    @app.get("/api/v1/devices")
    async def devices(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Return devices including the sample user-summary expansion."""
        return synthetic_page(
            request, load_json("devices.json"), limit=limit, after=after
        )

    @app.get("/api/v1/policies")
    async def policies(type: str) -> Any:
        """Wrap the single policy sample and filter by requested policy type."""
        policy = load_json("policies.json")
        return [policy] if policy["type"] == type else []

    @app.get("/api/v1/realms")
    async def realms() -> Any:
        """Return sample realms."""
        return load_json("realms.json")

    @app.get("/api/v1/idps")
    async def identity_providers() -> Any:
        """Return sample identity providers."""
        return load_json("idps.json")

    @app.get("/api/v1/authorizationServers")
    async def authorization_servers() -> Any:
        """Return sample authorization servers."""
        return load_json("auth_servers.json")

    @app.get("/api/v1/agentPools")
    async def agent_pools() -> Any:
        """Return the existing agent-pool sample without repairing its contents."""
        return load_json("agent_pools.json")

    @app.get("/api/v1/iam/resource-sets")
    async def resource_sets(
        request: Request,
        limit: PageLimit = DEFAULT_PAGE_SIZE,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> Any:
        """Wrap sample resource sets in the documented response envelope."""
        return synthetic_page(
            request,
            {"resource-sets": load_json("resource_sets.json")},
            limit=limit,
            after=after,
            key="resource-sets",
        )

    @app.get("/api/v1/api-tokens")
    async def api_tokens() -> Any:
        """Return sample API-token metadata."""
        return load_json("api_tokens.json")

    @app.get("/integrations/api/v1/api-services")
    async def api_services() -> Any:
        """Return sample API-service integrations."""
        return load_json("api_services.json")

    return app


@pytest.fixture
def rate_limited_okta_api(mock_okta_api: FastAPI) -> FastAPI:
    """Enable the shared high-volume dataset without changing sample-only tests."""
    mock_okta_api.state.page_counts = DEFAULT_PAGE_COUNTS.copy()
    return mock_okta_api


@pytest.fixture
def mock_okta_service(
    mock_okta_api: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """Route DLT requests into FastAPI without simulating Requests transport/retries."""
    with TestClient(mock_okta_api, base_url="https://okta.test") as client:

        def mock_request(
            rest_client: RESTClient, request: requests.Request, **kwargs: Any
        ) -> httpx2.Response:
            """Preserve prepared headers, query parameters, and body in TestClient."""
            prepared = rest_client.session.prepare_request(request)
            assert prepared.url is not None
            assert prepared.method is not None
            url = urlsplit(prepared.url)
            assert (url.scheme, url.netloc) == ("https", "okta.test"), (
                f"Unexpected external request: {prepared.url}"
            )
            return client.request(
                method=prepared.method,
                url=prepared.url,
                headers=dict(prepared.headers),
                content=prepared.body,
                follow_redirects=False,
            )

        monkeypatch.setattr(RESTClient, "_send_request", mock_request)
        yield client


@pytest.fixture
def okta_credentials(mock_okta_service: TestClient) -> OktaTokenCredentials:
    """Provide explicit local credentials without reading DLT secrets."""
    return OktaTokenCredentials(
        base_url=str(mock_okta_service.base_url), token="test-token"
    )


@pytest.fixture
def okta_client(okta_credentials: OktaTokenCredentials) -> ClientPool:
    """Use the collector's real HTTP client and authentication wiring."""
    return ClientPool(
        base_url=okta_credentials.base_url,
        auth=_request_auth(okta_credentials),
        paginator=HeaderLinkPaginator(),
    )


def test_collector_client_uses_mock_okta_api(
    mock_okta_api: FastAPI, okta_client: ClientPool
) -> None:
    """Verify collector requests reach the FastAPI mock and return its sample data."""
    response = okta_client.get("/api/v1/org")

    assert response.status_code == 200
    assert response.json() == load_json("organization.json")
    assert [request["path"] for request in mock_okta_api.state.requests] == [
        "/api/v1/org"
    ]


def test_response_contains_rate_limit_headers(
    mock_okta_api: FastAPI, okta_client: ClientPool
) -> None:
    """Verify the first organization request reports its bucket budget and reset."""
    response = okta_client.get("/api/v1/org")

    assert response.headers["X-Rate-Limit-Limit"] == "500"
    assert response.headers["X-Rate-Limit-Remaining"] == "499"
    assert response.headers["X-Rate-Limit-Reset"] == str(
        int(mock_okta_api.state.rate_limits.now + 60)
    )


def test_response_rate_limit_counter(
    mock_okta_api: FastAPI, okta_client: ClientPool
) -> None:
    init_response = okta_client.get("/api/v1/users")
    rate_limit = int(init_response.headers["X-Rate-Limit-Limit"])
    for item in range(2, 20):
        response = okta_client.get("/api/v1/users")
        assert int(response.headers["X-Rate-Limit-Remaining"]) == rate_limit - item


def test_synthetic_data_count(mock_okta_api: FastAPI, okta_client: ClientPool) -> None:
    """Verify three synthetic pages of five users return fifteen records."""
    mock_okta_api.state.page_counts = {r"/api/v1/users": 3}

    users = [
        user
        for page in okta_client.paginate("/api/v1/users", params={"limit": 5})
        for user in page
    ]

    assert len(users) == 15


def test_response_rate_limit_enforced(okta_client: ClientPool) -> None:
    """Allow the configured request budget, then reject the next request with 429."""
    response = okta_client.get("/api/v1/users")
    assert response.status_code == 200
    rate_limit = int(response.headers["X-Rate-Limit-Limit"])

    for _ in range(rate_limit - 1):
        assert okta_client.get("/api/v1/users").status_code == 200

    response = okta_client.get("/api/v1/users")
    assert response.status_code == 429
    assert response.headers["X-Rate-Limit-Remaining"] == "0"
