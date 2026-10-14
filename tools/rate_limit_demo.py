"""Visual sanity check of the collector's rate limit throttling.

Runs two independent collectors against a fake Okta that enforces per-endpoint
rate limits, an org-wide concurrency limit, and short outages, and shows live
progress bars for both sides: what the server has left to give, and how each
collector paces itself, backs off, and recovers. Use it to eyeball throttle
changes before relying on the unit tests alone. Run from the repository root:

    python -m tools.rate_limit_demo
"""

import math
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from fnmatch import fnmatch
from threading import BoundedSemaphore, Lock
from typing import Any
from urllib.parse import urlparse

import requests
from requests import PreparedRequest
from requests.adapters import BaseAdapter
from dlt.sources.helpers.requests.session import Session
from rich.console import RenderableType
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    Task,
    TaskID,
    TextColumn,
)
from rich.text import Text

from openhound_okta.telemetry import NullTelemetryRecorder, Telemetry
from openhound_okta.utils.http import (
    DEFAULT_ORG_CONCURRENCY,
    EndpointThrottle,
    OktaRESTClient,
)

# Base URL of the fake Okta organization.
BASE_URL: str = "https://example.okta.test"
# Endpoint families the fake Okta limits separately: family pattern to the
# URL template of one request in it.
ENDPOINTS: dict[str, str] = {
    "/api/v1/users/*/factors": "/api/v1/users/{id}/factors",
    "/api/v1/apps/*/users": "/api/v1/apps/{id}/users",
}
# Requests the fake Okta allows per window, for each endpoint family.
RATE_LIMIT: int = 500
# Okta's per-org cap on simultaneous transactions on production orgs (35 on
# the Integrator Free plan); arrivals above it are rejected with 429.
ORG_CONCURRENCY_LIMIT: int = 75
# Length of the fake Okta rate limit window.
WINDOW_SECONDS: int = 60
# Pause before every successful fake Okta response.
LATENCY_SECONDS: int = 3
# Pause before a 429 or 503 response, which the server rejects early.
ERROR_LATENCY_SECONDS: int = 1
# Period of the fake Okta's recurring outage, measured from its first request.
OUTAGE_EVERY_SECONDS: int = 90
# Length of each outage, during which every request is answered with 503.
OUTAGE_SECONDS: int = 1
# Users each collector fetches on each endpoint.
USER_COUNT: int = 1000
# Parallel workers per collector and endpoint. Saturating one limit needs
# RATE_LIMIT * LATENCY_SECONDS / WINDOW_SECONDS (25) requests in flight.
WORKERS: int = 32
# Collectors competing for the same server budgets.
COLLECTORS: int = 2
# How often the bars' status text is refreshed.
REFRESH_SECONDS: float = 0.25


def endpoint_family(path: str) -> str:
    """Map a request path to the ENDPOINTS family that rate-limits it.

    Args:
        path: The URL path of the request.

    Returns:
        The matching family pattern.

    Raises:
        ValueError: If no family in ENDPOINTS matches the path.
    """
    for pattern in ENDPOINTS:
        if fnmatch(path, pattern):
            return pattern
    raise ValueError(f"no endpoint family for {path}")


class FixedWindowLimiter:
    """One endpoint family's window budget on the fake Okta."""

    def __init__(self) -> None:
        """Start with an expired window so the first request opens a new one."""
        self.reset_at: float = 0.0
        self.remaining: int = 0
        self.admitted_count: int = 0
        self.rate_limited_count: int = 0

    def admit(self, now: float) -> bool:
        """Count one request against the window, opening a new one if due.

        Args:
            now: The epoch second the request arrived.

        Returns:
            True if the request fits the budget, False if it is rejected.
        """
        if now >= self.reset_at:
            self.reset_at = now + WINDOW_SECONDS
            self.remaining = RATE_LIMIT
        if self.remaining > 0:
            self.remaining -= 1
            self.admitted_count += 1
            return True
        self.rate_limited_count += 1
        return False


class RateLimitedOktaAdapter(BaseAdapter):
    """Fake Okta transport: fixed-window rate limiters with Okta's headers.

    Every request is counted against its endpoint family's current window on
    arrival and then answered after LATENCY_SECONDS. Requests beyond the
    window budget get a 429 with Retry-After pointing at the window reset.
    Arrivals while ORG_CONCURRENCY_LIMIT requests are already in flight get a
    429 with zeroed rate limit headers, as Okta reports concurrency
    violations, and do not count against any window. For the last
    OUTAGE_SECONDS of every OUTAGE_EVERY_SECONDS the server is down: requests
    get a bare 503 and do not count against any window either. Rejections
    are answered after the shorter ERROR_LATENCY_SECONDS.
    """

    def __init__(self) -> None:
        """Start with no windows open and nothing in flight."""
        self._lock = Lock()
        self._started_at: float = 0.0
        self._limiters: dict[str, FixedWindowLimiter] = {
            family: FixedWindowLimiter() for family in ENDPOINTS
        }
        self._in_flight: int = 0
        self.server_error_count: int = 0
        self.concurrency_limited_count: int = 0

    def send(
        self, request: PreparedRequest, *args: Any, **kwargs: Any
    ) -> requests.Response:
        """Count the request against its family's window and answer after a latency.

        Args:
            request: The prepared request; its path picks the family and its
                URL is echoed back.
            *args: Transport options passed by requests, ignored.
            **kwargs: Transport options passed by requests, ignored.

        Returns:
            A 200 response with one item, a 429 once the window budget is
            spent or the org concurrency limit is reached, or a 503 during an
            outage.
        """
        limiter = self._limiters[endpoint_family(urlparse(request.url or "").path)]
        with self._lock:
            now = time.time()
            if self._started_at == 0.0:
                self._started_at = now
            headers: dict[str, str] = {}
            in_outage = (
                now - self._started_at
            ) % OUTAGE_EVERY_SECONDS >= OUTAGE_EVERY_SECONDS - OUTAGE_SECONDS
            admitted = self._in_flight < ORG_CONCURRENCY_LIMIT
            if admitted:
                self._in_flight += 1
            if in_outage:
                self.server_error_count += 1
                status_code = 503
            elif not admitted:
                self.concurrency_limited_count += 1
                status_code = 429
                headers = {
                    "X-Rate-Limit-Limit": "0",
                    "X-Rate-Limit-Remaining": "0",
                    "X-Rate-Limit-Reset": str(int(now)),
                }
            else:
                status_code = 200 if limiter.admit(now) else 429
                headers = {
                    "X-Rate-Limit-Limit": str(RATE_LIMIT),
                    "X-Rate-Limit-Remaining": str(limiter.remaining),
                    "X-Rate-Limit-Reset": str(int(limiter.reset_at)),
                }
            reset_at = limiter.reset_at

        time.sleep(LATENCY_SECONDS if status_code == 200 else ERROR_LATENCY_SECONDS)
        if admitted:
            with self._lock:
                self._in_flight -= 1
        if status_code == 429 and admitted:
            # Relative to the response, like a real server would compute it.
            headers["Retry-After"] = str(max(math.ceil(reset_at - time.time()), 0))
        response = requests.Response()
        response.status_code = status_code
        response.url = request.url or BASE_URL
        response.headers.update(headers)
        response._content = b'[{"id":"ost1","factorType":"push"}]'
        response.request = request
        return response

    def close(self) -> None:
        """Nothing to release; the adapter holds no connections."""

    @property
    def in_flight(self) -> int:
        """Requests the fake Okta is processing right now, across all clients."""
        with self._lock:
            return self._in_flight

    def snapshot(self, family: str) -> tuple[int, float, int, int]:
        """Return one family's remaining budget, reset time, and counts.

        Args:
            family: A family pattern from ENDPOINTS.

        Returns:
            The remaining requests, the epoch second the window resets at,
            the admitted requests so far, and the 429 responses so far, as of
            the last request that arrived.
        """
        with self._lock:
            limiter = self._limiters[family]
            return (
                limiter.remaining,
                limiter.reset_at,
                limiter.admitted_count,
                limiter.rate_limited_count,
            )


def build_collector(
    adapter: RateLimitedOktaAdapter,
    family: str,
    telemetry: Telemetry,
    org_gate: BoundedSemaphore,
) -> OktaRESTClient:
    """Build a collector: the real client and throttle bound to the fake Okta.

    Args:
        adapter: The fake Okta transport the collector's session sends through.
        family: The ENDPOINTS pattern the client's throttle paces.
        telemetry: Recorder that observes the collector's responses.
        org_gate: Org-wide in-flight gate shared with the collector's other
            clients.

    Returns:
        A client for the family with its own throttle.
    """
    session = Session(raise_for_status=False)
    session.mount("https://", adapter)
    return OktaRESTClient(
        base_url=BASE_URL,
        endpoint_family=family,
        throttle=EndpointThrottle(max_concurrency=WORKERS, org_gate=org_gate),
        session=session,
        telemetry=telemetry,
    )


class HeaderAwareColumn(ProgressColumn):
    """Wraps a progress column so rows flagged as headers render it blank."""

    def __init__(self, column: ProgressColumn) -> None:
        """Wrap the column.

        Args:
            column: The column to render for ordinary rows.
        """
        super().__init__()
        self._column = column

    def render(self, task: Task) -> RenderableType:
        """Render the wrapped column, or nothing for a header row.

        Args:
            task: The row being rendered; header rows carry a header field.

        Returns:
            The wrapped column's renderable, or empty text for a header.
        """
        if task.fields.get("header"):
            return Text("")
        return self._column.render(task)


class AlignedCountColumn(ProgressColumn):
    """Completed/total column whose completed count has a fixed width.

    Padding every row to the same width keeps the slashes aligned even when
    the totals differ, such as 75 for a concurrency gauge and 1000 for a
    progress bar.
    """

    def __init__(self, width: int) -> None:
        """Set the width of the completed count.

        Args:
            width: Digits the completed count is right-aligned to.
        """
        super().__init__()
        self._width = width

    def render(self, task: Task) -> RenderableType:
        """Render the padded completed count and the total.

        Args:
            task: The row being rendered.

        Returns:
            The count as text in rich's download style.
        """
        total = int(task.total) if task.total is not None else 0
        return Text(
            f"{int(task.completed):{self._width}d}/{total}", style="progress.download"
        )


class StatusCounter(NullTelemetryRecorder):
    """Telemetry recorder that counts one client's 429 and 5xx responses."""

    def __init__(self) -> None:
        """Start both counters at zero."""
        self._lock = Lock()
        self.rate_limited: int = 0
        self.server_errors: int = 0

    def record_http_response(self, endpoint: str, **values: Any) -> None:
        """Count the response by status class.

        Args:
            endpoint: The requested URL, unused.
            **values: The client's measurements; only status_code is read.
        """
        status_code = int(values["status_code"])
        with self._lock:
            if status_code == 429:
                self.rate_limited += 1
            elif status_code >= 500:
                self.server_errors += 1


class Job:
    """One collector's work on one endpoint family: its client, counts and bar."""

    def __init__(
        self,
        adapter: RateLimitedOktaAdapter,
        family: str,
        org_gate: BoundedSemaphore,
        task: TaskID,
    ) -> None:
        """Build the client for the family behind the collector's org gate.

        Args:
            adapter: The fake Okta transport the client sends through.
            family: The ENDPOINTS pattern this job walks.
            org_gate: The collector's org-wide in-flight gate.
            task: The bar belonging to this job.
        """
        self.family = family
        self.task = task
        self.counter = StatusCounter()
        self.client = build_collector(adapter, family, self.counter, org_gate)

    def run(self, progress: Progress) -> None:
        """Fetch every user on the family and advance the bar per response.

        Args:
            progress: The shared progress display.
        """

        def fetch(user_id: int) -> None:
            self.client.get(ENDPOINTS[self.family].format(id=user_id))

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = [
                pool.submit(fetch, user_id) for user_id in range(1, USER_COUNT + 1)
            ]
            for _ in as_completed(futures):
                progress.advance(self.task)

    def status(self, completed: float, elapsed: float) -> str:
        """Format the job's status text.

        Args:
            completed: Users fetched so far.
            elapsed: Seconds since the run started.

        Returns:
            The 429 and 5xx counts, requests in flight against the family
            cap, throughput, and elapsed time.
        """
        throughput = completed / elapsed * 60 if elapsed > 0 else 0.0
        return (
            f"429s: {self.counter.rate_limited:<4d} "
            f"5xx: {self.counter.server_errors:<4d} "
            f"in flight: {self.client.throttle.in_flight:2d}/{WORKERS}  "
            f"throughput: {throughput:5.1f}/min  "
            f"elapsed: {int(elapsed) // 60}:{int(elapsed) % 60:02d}"
        )


class Collector:
    """One collector: its org gate, gate gauge, and one job per endpoint."""

    def __init__(
        self, adapter: RateLimitedOktaAdapter, name: str, progress: Progress
    ) -> None:
        """Create the org gate, its header and gauge rows, and the jobs' bars.

        Args:
            adapter: The fake Okta transport the jobs send through.
            name: The collector's label.
            progress: The shared progress display the bars are added to.
        """
        self.org_gate = BoundedSemaphore(DEFAULT_ORG_CONCURRENCY)
        progress.add_task(name, total=0, status="", header=True)
        self.gate_task = progress.add_task(
            "  concurrency", total=DEFAULT_ORG_CONCURRENCY, completed=0, status=""
        )
        self.jobs = [
            Job(
                adapter,
                family,
                self.org_gate,
                progress.add_task(
                    f"  progress {family.removeprefix('/api/v1/')}",
                    total=USER_COUNT,
                    status="",
                ),
            )
            for family in ENDPOINTS
        ]

    @property
    def in_flight(self) -> int:
        """Requests in flight across the collector's jobs, held by its org gate."""
        return sum(job.client.throttle.in_flight for job in self.jobs)


def main() -> None:
    """Run the collectors and render the bars until every request is done."""
    adapter = RateLimitedOktaAdapter()
    columns = [
        TextColumn("{task.description:<30}"),
        HeaderAwareColumn(BarColumn(bar_width=40)),
        HeaderAwareColumn(AlignedCountColumn(len(str(USER_COUNT)))),
        TextColumn("{task.fields[status]}"),
    ]
    with Progress(*columns) as progress:
        progress.add_task("fake Okta server", total=0, status="", header=True)
        org_task = progress.add_task(
            "  org concurrency limit",
            total=ORG_CONCURRENCY_LIMIT,
            completed=0,
            status="",
        )
        budget_tasks = {
            family: progress.add_task(
                f"  rate limit {family.removeprefix('/api/v1/')}",
                total=RATE_LIMIT,
                completed=RATE_LIMIT,
                status="",
            )
            for family in ENDPOINTS
        }
        collectors = [
            Collector(adapter, f"collector {index + 1}", progress)
            for index in range(COLLECTORS)
        ]
        jobs = [job for collector in collectors for job in collector.jobs]
        started_at = time.monotonic()
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures: list[Future[None]] = [
                pool.submit(job.run, progress) for job in jobs
            ]
            finished: set[int] = set()
            while len(finished) < len(jobs):
                elapsed = time.monotonic() - started_at
                for index, job in enumerate(jobs):
                    if index in finished:
                        continue
                    if futures[index].done():
                        finished.add(index)
                    progress.update(
                        job.task,
                        status=job.status(progress.tasks[job.task].completed, elapsed),
                    )
                for collector in collectors:
                    progress.update(collector.gate_task, completed=collector.in_flight)
                for family, task in budget_tasks.items():
                    remaining, reset_at, admitted, rate_limited = adapter.snapshot(
                        family
                    )
                    seconds_to_reset = max(reset_at - time.time(), 0.0)
                    if seconds_to_reset == 0.0:
                        remaining = RATE_LIMIT
                    progress.update(
                        task,
                        completed=remaining,
                        status=(
                            f"resets in {seconds_to_reset:4.1f}s  "
                            f"429s: {rate_limited:<4d} "
                            f"throughput: {admitted / elapsed * 60:5.1f}/min"
                        ),
                    )
                completed = sum(progress.tasks[job.task].completed for job in jobs)
                progress.update(
                    org_task,
                    completed=adapter.in_flight,
                    status=(
                        f"429s: {adapter.concurrency_limited_count:<4d} "
                        f"503s: {adapter.server_error_count:<4d} "
                        f"throughput: {completed / elapsed * 60:6.1f}/min  "
                        f"latency: {LATENCY_SECONDS}s"
                    ),
                )
                time.sleep(REFRESH_SECONDS)
            for future in futures:
                future.result()


if __name__ == "__main__":
    main()
