"""Representative BED-9741 collection and graph-parity replay benchmark."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import re
import resource
import shutil
import statistics
import tempfile
import time
from pathlib import Path
from threading import Lock
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlparse

import dlt
import requests
from dlt.sources.helpers.requests.session import Session
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator
from openhound.core.collect import Collector
from openhound.core.convert import Converter, Method
from openhound.core.asset import BaseAsset
from openhound.core.lookup import LookupManager
from openhound.core.progress import Progress
from requests.adapters import BaseAdapter

from openhound_okta.models.application import Application
from openhound_okta.models.application_users import ApplicationUser
from openhound_okta.main import _extract_performance_settings_from_source
from openhound_okta.source import (
    APPLICATION_USERS_PAGE_SIZE,
    ClientPool,
    SourceContext,
    application_users,
)
from openhound_okta.telemetry import TelemetrySettings, build_telemetry
from openhound_okta.utils.http import EndpointThrottle, OktaRESTClient

REPETITIONS = 5
APPLICATIONS = 200
ASSIGNMENTS_PER_APPLICATION = 5_000
ROWS_PER_PAGE = APPLICATION_USERS_PAGE_SIZE
_CREATED = "2026-01-01T00:00:00Z"
_APP_PATH = re.compile(r"^/api/v1/apps/(?P<app_id>[^/]+)/users$")
_HASH_MODULUS = 1 << 256


class AssignmentReplayAdapter(BaseAdapter):
    """Generate deterministic paginated Okta responses without network I/O."""

    def __init__(self, assignments_per_application: int, rows_per_page: int):
        self.assignments_per_application = assignments_per_application
        self.rows_per_page = rows_per_page
        self.requests = 0
        self._lock = Lock()

    def send(self, request, **kwargs):
        parsed = urlparse(request.url)
        match = _APP_PATH.fullmatch(parsed.path)
        if match is None:
            raise AssertionError(f"unexpected replay path: {parsed.path}")
        query = parse_qs(parsed.query)
        offset = int(query.get("after", ["0"])[0])
        app_id = match.group("app_id")
        end = min(offset + self.rows_per_page, self.assignments_per_application)
        rows = [
            {
                "id": f"user-{app_id}-{index:07d}",
                "created": _CREATED,
                "profile": {},
                "status": "ACTIVE",
                "scope": "USER",
            }
            for index in range(offset, end)
        ]
        response = requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response.connection = self
        response.headers["Content-Type"] = "application/json"
        if end < self.assignments_per_application:
            response.headers["Link"] = (
                f'<https://replay.okta.test{parsed.path}?'
                f'{urlencode({"limit": self.rows_per_page, "after": end})}>; '
                'rel="next"'
            )
        response._content = json.dumps(rows, separators=(",", ":")).encode()
        with self._lock:
            self.requests += 1
        return response

    def close(self):
        pass


class ReplayPool(ClientPool):
    def __init__(self, adapter: AssignmentReplayAdapter, telemetry):
        session = Session(raise_for_status=False)
        session.mount("https://", adapter)
        self.client = OktaRESTClient(
            base_url="https://replay.okta.test",
            endpoint_family="/api/v1/apps*",
            throttle=EndpointThrottle(),
            paginator=HeaderLinkPaginator(),
            session=session,
            telemetry=telemetry,
        )
        self.telemetry = telemetry

    def paginate(self, path: str, **kwargs):
        for page in self.client.paginate(path, **kwargs):
            self.telemetry.record_page(path, len(page))
            yield page


def _application_rows(applications: int):
    for index in range(applications):
        app_id = f"app-{index:04d}"
        yield {
            "id": app_id,
            "orn": f"orn:okta:idp:replay:apps:{app_id}",
            "name": "bookmark",
            "label": f"Replay application {index}",
            "status": "ACTIVE",
            "created": _CREATED,
            "signOnMode": "BOOKMARK",
            "features": [],
        }


def _replay_source(applications: int, ctx: SourceContext):
    @dlt.resource(name="applications", columns=Application, parallelized=True)
    def replay_applications():
        yield from _application_rows(applications)

    @dlt.source(name="okta", section="source")
    def replay():
        applications_resource = replay_applications()
        return applications_resource | application_users(ctx)

    return replay()


def _graph_signature(output_path: Path) -> dict[str, int | str]:
    node_count = 0
    edge_count = 0
    digest_sum = 0
    digest_xor = 0
    for path in output_path.glob("*.json"):
        graph = json.loads(path.read_text())["graph"]
        for entity_type, entities in (
            ("node", graph["nodes"]),
            ("edge", graph["edges"]),
        ):
            if entity_type == "node":
                node_count += len(entities)
            else:
                edge_count += len(entities)
            for entity in entities:
                canonical = json.dumps(
                    {"entity_type": entity_type, "content": entity},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                value = int.from_bytes(hashlib.sha256(canonical).digest(), "big")
                digest_sum = (digest_sum + value) % _HASH_MODULUS
                digest_xor ^= value
    return {
        "nodes": node_count,
        "edges": edge_count,
        "digest_sum": f"{digest_sum:064x}",
        "digest_xor": f"{digest_xor:064x}",
    }


def run_once(
    enabled: bool,
    root: Path,
    repetition: int,
    *,
    applications: int = APPLICATIONS,
    assignments_per_application: int = ASSIGNMENTS_PER_APPLICATION,
    rows_per_page: int = ROWS_PER_PAGE,
) -> dict[str, Any]:
    run_root = root / f"run-{repetition}-telemetry-{enabled}"
    raw_path = run_root / "raw"
    graph_path = run_root / "graph"
    recorder = build_telemetry(
        TelemetrySettings.from_mapping(
            {
                "enabled": enabled,
                "output_directory": run_root / "telemetry",
                "reporting_interval_seconds": 3_600,
            }
        ),
        collection_output=raw_path,
    )
    adapter = AssignmentReplayAdapter(assignments_per_application, rows_per_page)
    ctx = SourceContext(
        pool=ReplayPool(adapter, recorder),
        tenant_domain="replay.okta.test",
        telemetry=recorder,
        application_users_page_size=rows_per_page,
    )

    pipeline_wall_started = time.perf_counter()
    pipeline_cpu_started = time.process_time()
    collection_wall_started = time.perf_counter()
    collection_cpu_started = time.process_time()
    source_object = _replay_source(applications, ctx)
    recorder.set_effective_settings(
        _extract_performance_settings_from_source(source_object)
    )
    collector = Collector(
        name="okta",
        output_path=raw_path,
        progress=Progress.log,
    )
    collector.run(source_object)
    recorder.finish("complete")
    collection_wall_seconds = time.perf_counter() - collection_wall_started
    collection_cpu_seconds = time.process_time() - collection_cpu_started

    converter = Converter(
        name="okta",
        input_path=raw_path / "okta",
        lookup=cast(LookupManager, object()),
        output_path=graph_path,
        source_kind="Okta",
        progress=Progress.log,
        method=Method.write,
    )
    converter.run(
        _replay_source(applications, ctx),
        [cast(BaseAsset, ApplicationUser)],
        {"tenant": "replay.okta.test"},
    )
    graph_signature = _graph_signature(graph_path)
    pipeline_wall_seconds = time.perf_counter() - pipeline_wall_started
    pipeline_cpu_seconds = time.process_time() - pipeline_cpu_started
    artifact_path = getattr(recorder, "artifact_path", None)
    artifact_bytes = (
        artifact_path.stat().st_size
        if artifact_path is not None and artifact_path.exists()
        else 0
    )
    telemetry_summary = None
    if artifact_path is not None and artifact_path.exists():
        summary = json.loads(artifact_path.read_text().splitlines()[-1])
        endpoint = summary["endpoints"]["/api/v1/apps/{app}/users"]
        telemetry_summary = {
            "collection_state": summary["collection_state"],
            "telemetry_state": summary["telemetry_state"],
            "effective_performance_settings": summary[
                "effective_performance_settings"
            ],
            "application_streams": summary["application_streams"],
            "attempts": endpoint["attempts"],
            "rows_yielded": endpoint["rows_yielded"],
        }
    result = {
        "enabled": enabled,
        "repetition": repetition,
        "collection_wall_seconds": round(collection_wall_seconds, 6),
        "collection_cpu_seconds": round(collection_cpu_seconds, 6),
        "pipeline_wall_seconds": round(pipeline_wall_seconds, 6),
        "pipeline_cpu_seconds": round(pipeline_cpu_seconds, 6),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "artifact_bytes": artifact_bytes,
        "http_requests": adapter.requests,
        "graph": graph_signature,
        "telemetry_summary": telemetry_summary,
    }
    shutil.rmtree(run_root)
    return result


def _worker(enabled: bool, root: Path, repetition: int, results) -> None:
    try:
        results.put({"result": run_once(enabled, root, repetition)})
    except BaseException as error:
        results.put(
            {
                "error": f"{error.__class__.__name__}: {error}",
                "enabled": enabled,
                "repetition": repetition,
            }
        )
        raise


def isolated_run(enabled: bool, root: Path, repetition: int) -> dict[str, Any]:
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    process = context.Process(
        target=_worker,
        args=(enabled, root, repetition, results),
    )
    process.start()
    message = results.get()
    process.join()
    if process.exitcode != 0 or "error" in message:
        raise RuntimeError(
            message.get("error", f"benchmark worker exited with {process.exitcode}")
        )
    return message["result"]


def _validate_parity(results: list[dict[str, Any]]) -> dict[str, int | str]:
    signatures = {json.dumps(result["graph"], sort_keys=True) for result in results}
    if len(signatures) != 1:
        raise RuntimeError("enabled and disabled graph signatures differ")
    signature = results[0]["graph"]
    expected_edges = APPLICATIONS * ASSIGNMENTS_PER_APPLICATION
    if signature["nodes"] != 0 or signature["edges"] != expected_edges:
        raise RuntimeError(
            f"unexpected graph cardinality: {signature}; expected {expected_edges} edges"
        )
    expected_requests = APPLICATIONS * (
        (ASSIGNMENTS_PER_APPLICATION + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE
    )
    for result in results:
        if result["http_requests"] != expected_requests:
            raise RuntimeError(f"unexpected HTTP request count: {result}")
        if result["enabled"]:
            summary = result["telemetry_summary"]
            if summary is None:
                raise RuntimeError("enabled replay did not write telemetry")
            if (
                summary["collection_state"] != "complete"
                or summary["telemetry_state"] != "complete"
                or summary["application_streams"] != {"completed": APPLICATIONS}
                or summary["attempts"] != expected_requests
                or summary["rows_yielded"] != expected_edges
            ):
                raise RuntimeError(f"unexpected telemetry summary: {summary}")
    return signature


def _performance_summary(results: list[dict[str, Any]]) -> dict[str, float]:
    disabled = [result for result in results if not result["enabled"]]
    enabled = [result for result in results if result["enabled"]]
    off_wall = statistics.median(
        result["collection_wall_seconds"] for result in disabled
    )
    on_wall = statistics.median(
        result["collection_wall_seconds"] for result in enabled
    )
    return {
        "disabled_median_collection_wall_seconds": off_wall,
        "enabled_median_collection_wall_seconds": on_wall,
        "collection_wall_overhead_percent": round(
            ((on_wall - off_wall) / off_wall) * 100.0,
            3,
        ),
        "disabled_median_collection_cpu_seconds": statistics.median(
            result["collection_cpu_seconds"] for result in disabled
        ),
        "enabled_median_collection_cpu_seconds": statistics.median(
            result["collection_cpu_seconds"] for result in enabled
        ),
        "disabled_median_peak_rss_kib": statistics.median(
            result["peak_rss_kib"] for result in disabled
        ),
        "enabled_median_peak_rss_kib": statistics.median(
            result["peak_rss_kib"] for result in enabled
        ),
    }


def main() -> None:
    results = []
    with tempfile.TemporaryDirectory(
        prefix="openhound-okta-collection-benchmark-"
    ) as directory:
        root = Path(directory)
        for repetition in range(1, REPETITIONS + 1):
            results.append(isolated_run(False, root, repetition))
            results.append(isolated_run(True, root, repetition))
    graph_signature = _validate_parity(results)
    print(
        json.dumps(
            {
                "benchmark_kind": "representative_collection_replay",
                "workload": {
                    "applications": APPLICATIONS,
                    "assignments_per_application": ASSIGNMENTS_PER_APPLICATION,
                    "rows_per_page": ROWS_PER_PAGE,
                    "assignments": APPLICATIONS * ASSIGNMENTS_PER_APPLICATION,
                },
                "graph_parity": graph_signature,
                "performance_summary": _performance_summary(results),
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
