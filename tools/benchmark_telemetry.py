"""Deterministic BED-9741 recorder-only telemetry microbenchmark."""

from __future__ import annotations

import json
import multiprocessing
import resource
import tempfile
import time
from pathlib import Path

from openhound_okta.telemetry import TelemetrySettings, build_telemetry

REPETITIONS = 5
APPLICATIONS = 200
PAGES_PER_APPLICATION = 10
ROWS_PER_PAGE = 500
SIMULATED_HTTP_SECONDS = 0.002


def run_once(
    enabled: bool, root: Path, repetition: int
) -> dict[str, int | float | bool]:
    output_directory = root / f"telemetry-{repetition}"
    recorder = build_telemetry(
        TelemetrySettings.from_mapping(
            {
                "enabled": enabled,
                "output_directory": output_directory,
                "reporting_interval_seconds": 3_600,
            }
        ),
        collection_output=root / "raw",
    )
    wall_started = time.perf_counter()
    cpu_started = time.process_time()
    for _application in range(APPLICATIONS):
        for _page in range(PAGES_PER_APPLICATION):
            time.sleep(SIMULATED_HTTP_SECONDS)
            endpoint = "/api/v1/apps/opaque/users"
            recorder.record_http_response(
                endpoint,
                status_code=200,
                duration_seconds=SIMULATED_HTTP_SECONDS,
                headers={},
                throttle_wait={
                    "slot_wait_seconds": 0.0,
                    "pacing_wait_seconds": 0.0,
                    "retry_backoff_wait_seconds": 0.0,
                    "queue_depth": 0,
                    "observed_concurrency": 2,
                },
            )
            recorder.record_page(endpoint, ROWS_PER_PAGE)
        recorder.record_application_stream("completed")
    recorder.finish("complete")
    cpu_seconds = time.process_time() - cpu_started
    wall_seconds = time.perf_counter() - wall_started
    artifact_path = getattr(recorder, "artifact_path", None)
    artifact_bytes = (
        artifact_path.stat().st_size
        if artifact_path is not None and artifact_path.exists()
        else 0
    )
    return {
        "enabled": enabled,
        "repetition": repetition,
        "wall_seconds": round(wall_seconds, 6),
        "cpu_seconds": round(cpu_seconds, 6),
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "artifact_bytes": artifact_bytes,
    }


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


def isolated_run(
    enabled: bool, root: Path, repetition: int
) -> dict[str, int | float | bool]:
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


def main() -> None:
    results = []
    with tempfile.TemporaryDirectory(
        prefix="openhound-okta-telemetry-benchmark-"
    ) as directory:
        root = Path(directory)
        for repetition in range(1, REPETITIONS + 1):
            results.append(isolated_run(False, root, repetition))
            results.append(isolated_run(True, root, repetition))
    print(
        json.dumps(
            {
                "benchmark_kind": "recorder_microbenchmark",
                "workload": {
                    "applications": APPLICATIONS,
                    "pages_per_application": PAGES_PER_APPLICATION,
                    "rows_per_page": ROWS_PER_PAGE,
                    "assignments": (
                        APPLICATIONS * PAGES_PER_APPLICATION * ROWS_PER_PAGE
                    ),
                    "simulated_http_seconds_per_page": SIMULATED_HTTP_SECONDS,
                },
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
