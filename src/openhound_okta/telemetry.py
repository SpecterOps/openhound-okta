"""Bounded, value-free collection telemetry for the Okta collector."""

from __future__ import annotations

import importlib.metadata
import json
import logging
import math
import os
import queue
import re
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
DEFAULT_OUTPUT_DIRECTORY = "./telemetry"
DEFAULT_REPORTING_INTERVAL_SECONDS = 60.0
DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_INTERVAL_RECORDS = 1_440
DEFAULT_QUEUE_CAPACITY = 16
MIN_MAX_FILE_BYTES = 64 * 1024
SUMMARY_RESERVE_BYTES = 32 * 1024
EXPORTER_JOIN_TIMEOUT_SECONDS = 1.0

_LATENCY_BUCKETS_MS = (
    1,
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    30_000,
)
_ENDPOINT_TEMPLATES = (
    (re.compile(r"^/api/v1/apps/[^/]+/users$"), "/api/v1/apps/{app}/users"),
    (re.compile(r"^/api/v1/apps/[^/]+/groups$"), "/api/v1/apps/{app}/groups"),
    (
        re.compile(r"^/api/v1/apps/[^/]+/sso/saml/metadata$"),
        "/api/v1/apps/{app}/sso/saml/metadata",
    ),
    (
        re.compile(r"^/api/v1/apps/[^/]+/credentials/[^/]+$"),
        "/api/v1/apps/{app}/credentials/{kind}",
    ),
    (re.compile(r"^/api/v1/apps/[^/]+/grants$"), "/api/v1/apps/{app}/grants"),
    (
        re.compile(r"^/api/v1/apps/[^/]+/group-push/mappings$"),
        "/api/v1/apps/{app}/group-push/mappings",
    ),
    (re.compile(r"^/api/v1/groups/[^/]+/users$"), "/api/v1/groups/{group}/users"),
    (re.compile(r"^/api/v1/groups/[^/]+/roles$"), "/api/v1/groups/{group}/roles"),
    (re.compile(r"^/api/v1/groups/[^/]+$"), "/api/v1/groups/{group}"),
    (re.compile(r"^/api/v1/users/[^/]+/[^/]+$"), "/api/v1/users/{user}/{subresource}"),
    (re.compile(r"^/api/v1/users/[^/]+$"), "/api/v1/users/{user}"),
    (re.compile(r"^/api/v1/idps/[^/]+/users$"), "/api/v1/idps/{idp}/users"),
    (
        re.compile(r"^/api/v1/idps/[^/]+/metadata\.xml$"),
        "/api/v1/idps/{idp}/metadata.xml",
    ),
    (
        re.compile(r"^/api/v1/iam/[^/]+/[^/]+(?:/[^/]+)*$"),
        "/api/v1/iam/{resource}/{id}/{subresource}",
    ),
    (
        re.compile(r"^/oauth2/v1/clients/[^/]+/roles(?:/[^/]+)*$"),
        "/oauth2/v1/clients/{client}/roles/{scope}",
    ),
    (
        re.compile(r"^/api/v1/policies/[^/]+/mappings$"),
        "/api/v1/policies/{policy}/mappings",
    ),
    (
        re.compile(r"^/integrations/api/v1/api-services/[^/]+/credentials/secrets$"),
        "/integrations/api/v1/api-services/{service}/credentials/secrets",
    ),
)
_COLLECTION_PATHS = {
    "/api/v1/agentPools",
    "/api/v1/api-services",
    "/api/v1/api-tokens",
    "/api/v1/apps",
    "/api/v1/authorizationServers",
    "/api/v1/devices",
    "/api/v1/groups",
    "/api/v1/idps",
    "/api/v1/iam/assignees/users",
    "/api/v1/iam/resource-sets",
    "/api/v1/iam/roles",
    "/api/v1/org",
    "/api/v1/policies",
    "/api/v1/realms",
    "/api/v1/resource-sets",
    "/api/v1/roles",
    "/api/v1/users",
    "/oauth2/v1/clients",
    "/integrations/api/v1/api-services",
}
_LIMITER_GROUPS = {
    "/api/v1/users*",
    "/api/v1/groups*",
    "/api/v1/apps*",
    "/api/v1/idps*",
    "/api/v1/iam*",
    "/api/v1/devices*",
    "/oauth2/v1/clients*",
    "*",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_endpoint_template(url_or_path: str) -> str:
    """Return an allowlisted endpoint template without host, query, or identifiers."""
    path = urlparse(url_or_path).path.rstrip("/") or "/"
    if path in _COLLECTION_PATHS:
        return path
    for pattern, template in _ENDPOINT_TEMPLATES:
        if pattern.fullmatch(path):
            return template
    return "other"


def _normalize_limiter_group(value: str | None) -> str:
    if value is None:
        return "unavailable"
    return value if value in _LIMITER_GROUPS else "other"


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"


def _error_category(error: BaseException) -> str:
    if isinstance(error, requests.ReadTimeout):
        return "read_timeout"
    if isinstance(error, requests.ConnectTimeout):
        return "connect_timeout"
    if isinstance(error, requests.Timeout):
        return "timeout"
    if isinstance(error, requests.ConnectionError):
        return "connection_error"
    if isinstance(error, requests.RequestException):
        return "request_error"
    return "collector_error"


def _status_category(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "success"
    if status_code == 429:
        return "rate_limited"
    if status_code == 401:
        return "unauthorized"
    if 400 <= status_code < 500:
        return "client_error"
    if 500 <= status_code < 600:
        return "server_error"
    return "other_http"


@dataclass(frozen=True)
class TelemetrySettings:
    """Validated non-secret settings read from ``config.toml``."""

    enabled: bool = False
    output_directory: Path = Path(DEFAULT_OUTPUT_DIRECTORY)
    reporting_interval_seconds: float = DEFAULT_REPORTING_INTERVAL_SECONDS
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_interval_records: int = DEFAULT_MAX_INTERVAL_RECORDS
    queue_capacity: int = DEFAULT_QUEUE_CAPACITY

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "TelemetrySettings":
        def configured(name: str, default: Any) -> Any:
            value = values.get(name)
            return default if value is None else value

        settings = cls(
            enabled=bool(values.get("enabled", False)),
            output_directory=Path(
                configured("output_directory", DEFAULT_OUTPUT_DIRECTORY)
            ),
            reporting_interval_seconds=float(
                configured(
                    "reporting_interval_seconds",
                    DEFAULT_REPORTING_INTERVAL_SECONDS,
                )
            ),
            max_file_bytes=int(configured("max_file_bytes", DEFAULT_MAX_FILE_BYTES)),
            max_interval_records=int(
                configured("max_interval_records", DEFAULT_MAX_INTERVAL_RECORDS)
            ),
            queue_capacity=int(configured("queue_capacity", DEFAULT_QUEUE_CAPACITY)),
        )
        if (
            not math.isfinite(settings.reporting_interval_seconds)
            or settings.reporting_interval_seconds <= 0
        ):
            raise ValueError(
                "telemetry.reporting_interval_seconds must be finite and positive"
            )
        if settings.max_file_bytes < MIN_MAX_FILE_BYTES:
            raise ValueError(
                f"telemetry.max_file_bytes must be at least {MIN_MAX_FILE_BYTES}"
            )
        if settings.max_interval_records < 1:
            raise ValueError("telemetry.max_interval_records must be at least 1")
        if settings.queue_capacity < 2:
            raise ValueError("telemetry.queue_capacity must be at least 2")
        return settings


@dataclass
class LatencyDistribution:
    count: int = 0
    total_seconds: float = 0.0
    minimum_seconds: float | None = None
    maximum_seconds: float | None = None
    buckets: list[int] = field(
        default_factory=lambda: [0] * (len(_LATENCY_BUCKETS_MS) + 1)
    )

    def observe(self, seconds: float) -> None:
        seconds = max(seconds, 0.0)
        self.count += 1
        self.total_seconds += seconds
        self.minimum_seconds = (
            seconds
            if self.minimum_seconds is None
            else min(self.minimum_seconds, seconds)
        )
        self.maximum_seconds = (
            seconds
            if self.maximum_seconds is None
            else max(self.maximum_seconds, seconds)
        )
        milliseconds = seconds * 1_000
        for index, upper_bound in enumerate(_LATENCY_BUCKETS_MS):
            if milliseconds <= upper_bound:
                self.buckets[index] += 1
                return
        self.buckets[-1] += 1

    def merge(self, other: "LatencyDistribution") -> None:
        if not other.count:
            return
        self.count += other.count
        self.total_seconds += other.total_seconds
        if other.minimum_seconds is not None:
            self.minimum_seconds = (
                other.minimum_seconds
                if self.minimum_seconds is None
                else min(self.minimum_seconds, other.minimum_seconds)
            )
        if other.maximum_seconds is not None:
            self.maximum_seconds = (
                other.maximum_seconds
                if self.maximum_seconds is None
                else max(self.maximum_seconds, other.maximum_seconds)
            )
        self.buckets = [
            left + right for left, right in zip(self.buckets, other.buckets)
        ]

    def as_dict(self) -> dict[str, Any]:
        return {
            "unit": "seconds",
            "sample_count": self.count,
            "sum": round(self.total_seconds, 6),
            "min": None
            if self.minimum_seconds is None
            else round(self.minimum_seconds, 6),
            "max": None
            if self.maximum_seconds is None
            else round(self.maximum_seconds, 6),
            "histogram_upper_bounds_ms": [*_LATENCY_BUCKETS_MS, "+Inf"],
            "histogram_counts": self.buckets,
            "quantile_upper_bounds_ms": {
                "p50": self._quantile_upper_bound(0.50),
                "p95": self._quantile_upper_bound(0.95),
                "p99": self._quantile_upper_bound(0.99),
            },
        }

    def _quantile_upper_bound(self, quantile: float) -> int | str | None:
        if not self.count:
            return None
        target = math.ceil(self.count * quantile)
        cumulative = 0
        upper_bounds: tuple[int | str, ...] = (*_LATENCY_BUCKETS_MS, "+Inf")
        for upper_bound, count in zip(upper_bounds, self.buckets):
            cumulative += count
            if cumulative >= target:
                return upper_bound
        return "+Inf"


@dataclass
class EndpointMeasurements:
    attempts: int = 0
    outcomes: Counter[str] = field(default_factory=Counter)
    transport_errors: Counter[str] = field(default_factory=Counter)
    retries: Counter[str] = field(default_factory=Counter)
    retry_delay_seconds: dict[str, float] = field(default_factory=dict)
    limiter_groups: set[str] = field(default_factory=set)
    queued_requests: int = 0
    max_queue_depth: int = 0
    max_observed_concurrency: int = 0
    pages_yielded: int = 0
    rows_yielded: int = 0
    row_count_unavailable_pages: int = 0
    slot_wait: LatencyDistribution = field(default_factory=LatencyDistribution)
    pacing_wait: LatencyDistribution = field(default_factory=LatencyDistribution)
    retry_wait: LatencyDistribution = field(default_factory=LatencyDistribution)
    http_execution: LatencyDistribution = field(default_factory=LatencyDistribution)
    quota: dict[str, Any] | None = None

    def merge(self, other: "EndpointMeasurements") -> None:
        self.attempts += other.attempts
        self.outcomes.update(other.outcomes)
        self.transport_errors.update(other.transport_errors)
        self.retries.update(other.retries)
        self.limiter_groups.update(other.limiter_groups)
        for category, seconds in other.retry_delay_seconds.items():
            self.retry_delay_seconds[category] = (
                self.retry_delay_seconds.get(category, 0.0) + seconds
            )
        self.queued_requests += other.queued_requests
        self.max_queue_depth = max(self.max_queue_depth, other.max_queue_depth)
        self.max_observed_concurrency = max(
            self.max_observed_concurrency, other.max_observed_concurrency
        )
        self.pages_yielded += other.pages_yielded
        self.rows_yielded += other.rows_yielded
        self.row_count_unavailable_pages += other.row_count_unavailable_pages
        self.slot_wait.merge(other.slot_wait)
        self.pacing_wait.merge(other.pacing_wait)
        self.retry_wait.merge(other.retry_wait)
        self.http_execution.merge(other.http_execution)
        if other.quota is not None:
            self.quota = other.quota

    def as_dict(self, elapsed_seconds: float) -> dict[str, Any]:
        return {
            "collector_limiter_groups": sorted(self.limiter_groups) or ["unavailable"],
            "provider_bucket_identity": "unverified",
            "attempts": self.attempts,
            "outcomes": dict(sorted(self.outcomes.items())),
            "transport_errors": dict(sorted(self.transport_errors.items())),
            "retries": dict(sorted(self.retries.items())),
            "retry_delay_seconds": {
                key: round(value, 6)
                for key, value in sorted(self.retry_delay_seconds.items())
            },
            "queued_requests": self.queued_requests,
            "max_queue_depth": self.max_queue_depth,
            "max_observed_concurrency": self.max_observed_concurrency,
            "pages_yielded": self.pages_yielded,
            "rows_yielded": self.rows_yielded,
            "row_count_unavailable_pages": self.row_count_unavailable_pages,
            "requests_per_second": round(self.attempts / elapsed_seconds, 6)
            if elapsed_seconds > 0
            else None,
            "rows_per_second": round(self.rows_yielded / elapsed_seconds, 6)
            if elapsed_seconds > 0
            else None,
            "slot_wait": self.slot_wait.as_dict(),
            "proactive_pacing_wait": self.pacing_wait.as_dict(),
            "retry_backoff_wait": self.retry_wait.as_dict(),
            "http_execution": self.http_execution.as_dict(),
            "latest_quota_observation": self.quota or {"state": "unavailable"},
        }


class TelemetryRecorder:
    """Incrementally aggregate telemetry and export bounded JSONL records."""

    def __init__(
        self,
        settings: TelemetrySettings,
        *,
        collection_output: Path,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        open_file: Callable[..., TextIO] = open,
    ) -> None:
        self.settings = settings
        self.run_id = uuid.uuid4().hex
        self.artifact_path = (
            settings.output_directory / f"openhound-okta-{self.run_id}.jsonl"
        )
        self._clock = monotonic
        self._wall_clock = wall_clock
        self._open_file = open_file
        self._started_at = self._clock()
        self._interval_started_at = self._started_at
        self._lock = threading.Lock()
        self._interval: dict[str, EndpointMeasurements] = {}
        self._summary: dict[str, EndpointMeasurements] = {}
        self._app_interval = Counter[str]()
        self._app_summary = Counter[str]()
        self._effective_settings: dict[str, int | float] = {}
        self._sequence = 0
        self._interval_records = 0
        self._dropped_records = 0
        self._output_truncated = False
        self._exporter_error = False
        self._drop_diagnostic_logged = False
        self._finished = False
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(
            maxsize=settings.queue_capacity
        )
        self._writer_stop = threading.Event()
        self._flusher_stop = threading.Event()
        self._writer = threading.Thread(
            target=self._writer_loop,
            name="okta-telemetry-writer",
            daemon=True,
        )
        self._flusher = threading.Thread(
            target=self._flusher_loop,
            name="okta-telemetry-flusher",
            daemon=True,
        )
        self._safe_output = not self._is_within(
            settings.output_directory, collection_output
        )
        if not self._safe_output:
            self._exporter_error = True
            logger.warning(
                "Okta telemetry disabled error_category=unsafe_output_location"
            )
            return
        self._writer.start()
        self._flusher.start()
        self._enqueue(
            {
                "schema_version": SCHEMA_VERSION,
                "record_type": "run_start",
                "run_id": self.run_id,
                "state": "incomplete",
                "collection_state": "incomplete",
                "telemetry_state": "incomplete",
                "recorded_at": _utc_now(),
                "measurement_definitions": {
                    "durations": "monotonic seconds",
                    "http_execution": "request send through response-body transfer; excludes JSON decoding and downstream row conversion",
                    "wait_attribution": "summed worker wait samples; not additive wall-clock attribution",
                    "rows_yielded": "rows returned by API pagination; not committed collector output",
                    "quota_identity": "collector limiter groups are not verified Okta provider buckets",
                },
            },
            priority=True,
        )

    @staticmethod
    def _is_within(candidate: Path, parent: Path) -> bool:
        candidate_resolved = candidate.expanduser().resolve()
        parent_resolved = parent.expanduser().resolve()
        return (
            candidate_resolved == parent_resolved
            or parent_resolved in candidate_resolved.parents
        )

    @property
    def active(self) -> bool:
        return self.settings.enabled and self._safe_output and not self._finished

    def set_effective_settings(self, values: Mapping[str, int | float]) -> None:
        if not self.active:
            return
        with self._lock:
            self._effective_settings.update(values)

    def record_throttle_wait(
        self,
        endpoint: str,
        *,
        slot_wait_seconds: float,
        pacing_wait_seconds: float,
        retry_backoff_wait_seconds: float,
        queue_depth: int,
        observed_concurrency: int,
    ) -> None:
        if not self.active:
            return
        with self._lock:
            aggregate = self._aggregate(endpoint)
            aggregate.queued_requests += int(queue_depth > 0)
            aggregate.max_queue_depth = max(aggregate.max_queue_depth, queue_depth)
            aggregate.max_observed_concurrency = max(
                aggregate.max_observed_concurrency, observed_concurrency
            )
            aggregate.slot_wait.observe(slot_wait_seconds)
            aggregate.pacing_wait.observe(pacing_wait_seconds)
            aggregate.retry_wait.observe(retry_backoff_wait_seconds)
        self._flush_if_due()

    def record_http_response(
        self,
        endpoint: str,
        *,
        status_code: int,
        duration_seconds: float,
        headers: Mapping[str, str],
        throttle_wait: Mapping[str, int | float] | None = None,
        limiter_group: str | None = None,
    ) -> None:
        if not self.active:
            return
        quota = self._quota_observation(headers)
        with self._lock:
            aggregate = self._aggregate(endpoint)
            aggregate.limiter_groups.add(_normalize_limiter_group(limiter_group))
            self._record_throttle_measurements(aggregate, throttle_wait)
            aggregate.attempts += 1
            aggregate.outcomes[_status_category(status_code)] += 1
            aggregate.http_execution.observe(duration_seconds)
            aggregate.quota = quota
        self._flush_if_due()

    def record_transport_error(
        self,
        endpoint: str,
        *,
        error: BaseException,
        duration_seconds: float,
        throttle_wait: Mapping[str, int | float] | None = None,
        limiter_group: str | None = None,
    ) -> None:
        if not self.active:
            return
        category = _error_category(error)
        with self._lock:
            aggregate = self._aggregate(endpoint)
            aggregate.limiter_groups.add(_normalize_limiter_group(limiter_group))
            self._record_throttle_measurements(aggregate, throttle_wait)
            aggregate.attempts += 1
            aggregate.outcomes["transport_error"] += 1
            aggregate.transport_errors[category] += 1
            aggregate.http_execution.observe(duration_seconds)
        self._flush_if_due()

    def record_retry(
        self, endpoint: str, *, category: str, delay_seconds: float
    ) -> None:
        if not self.active:
            return
        with self._lock:
            aggregate = self._aggregate(endpoint)
            aggregate.retries[category] += 1
            aggregate.retry_delay_seconds[category] = aggregate.retry_delay_seconds.get(
                category, 0.0
            ) + max(delay_seconds, 0.0)

    def record_retry_wait(self, endpoint: str, *, duration_seconds: float) -> None:
        if not self.active:
            return
        with self._lock:
            self._aggregate(endpoint).retry_wait.observe(duration_seconds)

    def record_page(self, endpoint: str, row_count: int | None) -> None:
        if not self.active:
            return
        with self._lock:
            aggregate = self._aggregate(endpoint)
            aggregate.pages_yielded += 1
            if row_count is None:
                aggregate.row_count_unavailable_pages += 1
            else:
                aggregate.rows_yielded += max(row_count, 0)

    def record_application_stream(self, state: str) -> None:
        if not self.active:
            return
        with self._lock:
            self._app_interval[state] += 1

    def finish(self, state: str, error: BaseException | None = None) -> None:
        if self._finished:
            return
        self._finished = True
        if not self._safe_output:
            return
        self._flusher_stop.set()
        self._flusher.join(timeout=EXPORTER_JOIN_TIMEOUT_SECONDS)
        self.flush(force=True)
        elapsed = max(self._clock() - self._started_at, 0.0)
        with self._lock:
            endpoints = {
                name: metrics.as_dict(elapsed)
                for name, metrics in sorted(self._summary.items())
            }
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_type": "run_summary",
                "run_id": self.run_id,
                "state": state,
                "collection_state": state,
                "telemetry_state": "complete",
                "recorded_at": _utc_now(),
                "elapsed_seconds": round(elapsed, 6),
                "failure_category": _error_category(error) if error else None,
                "components": {
                    "collector": _version("openhound-okta"),
                    "openhound_core": _version("openhound"),
                    "dlt": _version("dlt"),
                },
                "effective_performance_settings": self._effective_settings,
                "effective_telemetry_settings": {
                    "reporting_interval_seconds": (
                        self.settings.reporting_interval_seconds
                    ),
                    "max_file_bytes": self.settings.max_file_bytes,
                    "max_interval_records": self.settings.max_interval_records,
                    "queue_capacity": self.settings.queue_capacity,
                },
                "application_streams": dict(sorted(self._app_summary.items())),
                "endpoints": endpoints,
                "export": {
                    "dropped_records": self._dropped_records,
                    "output_truncated": self._output_truncated,
                    "exporter_error": self._exporter_error,
                },
            }
        self._enqueue(record, priority=True)
        self._writer_stop.set()
        self._writer.join(timeout=EXPORTER_JOIN_TIMEOUT_SECONDS)
        if self._writer.is_alive():
            logger.warning("Okta telemetry incomplete error_category=exporter_timeout")

    def flush(self, *, force: bool = False) -> None:
        if not self._safe_output:
            return
        now = self._clock()
        with self._lock:
            if not self._interval and not self._app_interval:
                self._interval_started_at = now
                return
            elapsed = max(now - self._interval_started_at, 0.0)
            if not force and elapsed < self.settings.reporting_interval_seconds:
                return
            self._sequence += 1
            for name, metrics in self._interval.items():
                self._summary.setdefault(name, EndpointMeasurements()).merge(metrics)
            self._app_summary.update(self._app_interval)
            endpoints = {
                name: metrics.as_dict(elapsed)
                for name, metrics in sorted(self._interval.items())
            }
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_type": "interval",
                "run_id": self.run_id,
                "sequence": self._sequence,
                "recorded_at": _utc_now(),
                "interval": {
                    "start_elapsed_seconds": round(
                        self._interval_started_at - self._started_at, 6
                    ),
                    "end_elapsed_seconds": round(now - self._started_at, 6),
                    "elapsed_seconds": round(elapsed, 6),
                },
                "application_streams": dict(sorted(self._app_interval.items())),
                "endpoints": endpoints,
            }
            self._interval = {}
            self._app_interval = Counter()
            self._interval_started_at = now
            if self._interval_records >= self.settings.max_interval_records:
                self._dropped_records += 1
                self._output_truncated = True
                self._log_drop("interval_record_limit")
                return
            self._interval_records += 1
        self._enqueue(record)

    def _flush_if_due(self) -> None:
        if (
            self._clock() - self._interval_started_at
            >= self.settings.reporting_interval_seconds
        ):
            self.flush()

    def _flusher_loop(self) -> None:
        while not self._flusher_stop.wait(self.settings.reporting_interval_seconds):
            self.flush(force=True)

    def _aggregate(self, endpoint: str) -> EndpointMeasurements:
        template = normalize_endpoint_template(endpoint)
        return self._interval.setdefault(template, EndpointMeasurements())

    @staticmethod
    def _record_throttle_measurements(
        aggregate: EndpointMeasurements,
        values: Mapping[str, int | float] | None,
    ) -> None:
        if values is None:
            return
        queue_depth = int(values["queue_depth"])
        aggregate.queued_requests += int(queue_depth > 0)
        aggregate.max_queue_depth = max(aggregate.max_queue_depth, queue_depth)
        aggregate.max_observed_concurrency = max(
            aggregate.max_observed_concurrency,
            int(values["observed_concurrency"]),
        )
        aggregate.slot_wait.observe(float(values["slot_wait_seconds"]))
        aggregate.pacing_wait.observe(float(values["pacing_wait_seconds"]))
        aggregate.retry_wait.observe(float(values["retry_backoff_wait_seconds"]))

    def _quota_observation(self, headers: Mapping[str, str]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for artifact_name, header_name, parser in (
            ("limit", "X-Rate-Limit-Limit", int),
            ("remaining", "X-Rate-Limit-Remaining", int),
            ("reset_epoch_seconds", "X-Rate-Limit-Reset", float),
        ):
            raw = headers.get(header_name)
            if raw is None:
                fields[artifact_name] = {"state": "missing", "value": None}
                continue
            try:
                value = parser(raw.strip())
                if value < 0 or (isinstance(value, float) and not math.isfinite(value)):
                    raise ValueError
            except (TypeError, ValueError):
                fields[artifact_name] = {"state": "invalid", "value": None}
            else:
                fields[artifact_name] = {"state": "valid", "value": value}
        retry_after = headers.get("Retry-After")
        if retry_after is None:
            fields["retry_after_seconds"] = {"state": "missing", "value": None}
        else:
            try:
                value = float(retry_after.strip())
                if not math.isfinite(value) or value < 0:
                    raise ValueError
            except (TypeError, ValueError):
                try:
                    value = max(
                        parsedate_to_datetime(retry_after).timestamp()
                        - self._wall_clock(),
                        0.0,
                    )
                except (TypeError, ValueError, OverflowError):
                    fields["retry_after_seconds"] = {
                        "state": "invalid",
                        "value": None,
                    }
                else:
                    fields["retry_after_seconds"] = {
                        "state": "valid",
                        "value": round(value, 6),
                    }
            else:
                fields["retry_after_seconds"] = {
                    "state": "valid",
                    "value": value,
                }
        reset = fields["reset_epoch_seconds"]
        freshness = None
        state = "unavailable"
        if reset["state"] == "valid":
            freshness = float(reset["value"]) - self._wall_clock()
            state = "stale" if freshness < 0 else "current"
        return {
            "state": state,
            "observed_elapsed_seconds": round(self._clock() - self._started_at, 6),
            "reset_freshness_seconds": None
            if freshness is None
            else round(freshness, 6),
            "headers": fields,
        }

    def _enqueue(
        self, record: dict[str, Any] | None, *, priority: bool = False
    ) -> None:
        try:
            self._queue.put_nowait(record)
            return
        except queue.Full:
            self._dropped_records += 1
            self._log_drop("export_queue_full")
        if not priority:
            return
        try:
            self._queue.get_nowait()
            self._queue.task_done()
            self._queue.put_nowait(record)
        except (queue.Empty, queue.Full):
            self._exporter_error = True
            logger.warning("Okta telemetry incomplete error_category=export_queue_full")

    def _writer_loop(self) -> None:
        file_handle: TextIO | None = None
        bytes_written = 0
        truncation_written = False
        try:
            self.settings.output_directory.expanduser().mkdir(
                parents=True, exist_ok=True
            )
            file_handle = self._open_file(
                self.artifact_path.expanduser(), "x", encoding="utf-8"
            )
            while not self._writer_stop.is_set() or not self._queue.empty():
                try:
                    record = self._queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                try:
                    if record is None:
                        continue
                    if record.get("record_type") == "run_summary":
                        record["export"]["dropped_records"] = self._dropped_records
                        record["export"]["output_truncated"] = self._output_truncated
                        record["export"]["exporter_error"] = self._exporter_error
                        record["telemetry_state"] = (
                            "incomplete"
                            if record["collection_state"] != "complete"
                            or self._dropped_records
                            or self._output_truncated
                            or self._exporter_error
                            else "complete"
                        )
                    encoded = (
                        json.dumps(
                            record,
                            separators=(",", ":"),
                            sort_keys=True,
                            allow_nan=False,
                        )
                        + os.linesep
                    ).encode("utf-8")
                    is_summary = record.get("record_type") == "run_summary"
                    data_limit = self.settings.max_file_bytes - SUMMARY_RESERVE_BYTES
                    if not is_summary and bytes_written + len(encoded) > data_limit:
                        self._output_truncated = True
                        self._log_drop("file_size_limit")
                        if not truncation_written:
                            status = (
                                json.dumps(
                                    {
                                        "schema_version": SCHEMA_VERSION,
                                        "record_type": "export_status",
                                        "run_id": self.run_id,
                                        "output_truncated": True,
                                    },
                                    separators=(",", ":"),
                                    sort_keys=True,
                                    allow_nan=False,
                                )
                                + os.linesep
                            ).encode("utf-8")
                            file_handle.write(status.decode("utf-8"))
                            file_handle.flush()
                            bytes_written += len(status)
                            truncation_written = True
                        continue
                    if bytes_written + len(encoded) > self.settings.max_file_bytes:
                        self._output_truncated = True
                        if is_summary:
                            record = {
                                "schema_version": SCHEMA_VERSION,
                                "record_type": "run_summary",
                                "run_id": self.run_id,
                                "state": record["state"],
                                "collection_state": record["collection_state"],
                                "telemetry_state": "incomplete",
                                "export": {
                                    "dropped_records": self._dropped_records,
                                    "output_truncated": True,
                                    "exporter_error": self._exporter_error,
                                },
                            }
                            encoded = (
                                json.dumps(
                                    record,
                                    separators=(",", ":"),
                                    sort_keys=True,
                                    allow_nan=False,
                                )
                                + os.linesep
                            ).encode("utf-8")
                            if (
                                bytes_written + len(encoded)
                                > self.settings.max_file_bytes
                            ):
                                continue
                        else:
                            continue
                    file_handle.write(encoded.decode("utf-8"))
                    file_handle.flush()
                    bytes_written += len(encoded)
                finally:
                    self._queue.task_done()
        except (OSError, ValueError, TypeError):
            self._exporter_error = True
            logger.warning("Okta telemetry incomplete error_category=exporter_failure")
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    return
        finally:
            if file_handle is not None:
                try:
                    file_handle.close()
                except OSError:
                    self._exporter_error = True

    def _log_drop(self, category: str) -> None:
        if self._drop_diagnostic_logged:
            return
        self._drop_diagnostic_logged = True
        logger.warning(
            "Okta telemetry incomplete error_category=%s",
            category,
        )


class NullTelemetryRecorder:
    """No-op recorder used when telemetry is disabled."""

    active = False
    artifact_path: Path | None = None

    def set_effective_settings(self, values: Mapping[str, int | float]) -> None:
        pass

    def record_throttle_wait(self, endpoint: str, **values: Any) -> None:
        pass

    def record_http_response(self, endpoint: str, **values: Any) -> None:
        pass

    def record_transport_error(self, endpoint: str, **values: Any) -> None:
        pass

    def record_retry(self, endpoint: str, **values: Any) -> None:
        pass

    def record_retry_wait(self, endpoint: str, **values: Any) -> None:
        pass

    def record_page(self, endpoint: str, row_count: int | None) -> None:
        pass

    def record_application_stream(self, state: str) -> None:
        pass

    def finish(self, state: str, error: BaseException | None = None) -> None:
        pass


class ResilientTelemetryRecorder:
    """Prevent instrumentation faults from changing collection behavior."""

    def __init__(self, recorder: TelemetryRecorder) -> None:
        self._recorder = recorder
        self._failed = False

    @property
    def active(self) -> bool:
        return not self._failed and self._recorder.active

    @property
    def artifact_path(self) -> Path:
        return self._recorder.artifact_path

    def _call(self, method: str, *args: Any, **kwargs: Any) -> None:
        if self._failed:
            return
        try:
            getattr(self._recorder, method)(*args, **kwargs)
        except Exception as error:
            self._failed = True
            logger.warning(
                "Okta telemetry disabled error_category=instrumentation_failure"
            )
            if method != "finish":
                try:
                    self._recorder.finish("incomplete", error)
                except Exception:
                    pass

    def set_effective_settings(self, values: Mapping[str, int | float]) -> None:
        self._call("set_effective_settings", values)

    def record_throttle_wait(self, endpoint: str, **values: Any) -> None:
        self._call("record_throttle_wait", endpoint, **values)

    def record_http_response(self, endpoint: str, **values: Any) -> None:
        self._call("record_http_response", endpoint, **values)

    def record_transport_error(self, endpoint: str, **values: Any) -> None:
        self._call("record_transport_error", endpoint, **values)

    def record_retry(self, endpoint: str, **values: Any) -> None:
        self._call("record_retry", endpoint, **values)

    def record_retry_wait(self, endpoint: str, **values: Any) -> None:
        self._call("record_retry_wait", endpoint, **values)

    def record_page(self, endpoint: str, row_count: int | None) -> None:
        self._call("record_page", endpoint, row_count)

    def record_application_stream(self, state: str) -> None:
        self._call("record_application_stream", state)

    def finish(self, state: str, error: BaseException | None = None) -> None:
        self._call("finish", state, error)


Telemetry = TelemetryRecorder | ResilientTelemetryRecorder | NullTelemetryRecorder


def build_telemetry(
    settings: TelemetrySettings, *, collection_output: Path
) -> Telemetry:
    if not settings.enabled:
        return NullTelemetryRecorder()
    try:
        recorder = TelemetryRecorder(settings, collection_output=collection_output)
    except (OSError, RuntimeError, ValueError):
        logger.warning("Okta telemetry disabled error_category=initialization_failure")
        return NullTelemetryRecorder()
    return ResilientTelemetryRecorder(recorder)
