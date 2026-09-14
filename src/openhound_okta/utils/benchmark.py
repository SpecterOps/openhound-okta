"""Process-liveness helpers shared by telemetry benchmarks."""

from queue import Empty
from typing import Any

WORKER_RESULT_POLL_SECONDS = 0.1
WORKER_RESULT_EXIT_GRACE_SECONDS = 1.0


def wait_for_worker_result(process: Any, results: Any) -> Any:
    """Return a worker message or fail promptly after an unreported exit."""
    while True:
        try:
            return results.get(timeout=WORKER_RESULT_POLL_SECONDS)
        except Empty:
            if process.is_alive():
                continue

            process.join()
            try:
                return results.get(timeout=WORKER_RESULT_EXIT_GRACE_SECONDS)
            except Empty:
                raise RuntimeError(
                    "benchmark worker exited with "
                    f"{process.exitcode} before reporting a result"
                ) from None
