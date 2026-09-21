"""Process-liveness helpers shared by telemetry benchmarks."""

import sys
from queue import Empty
from typing import Any

WORKER_RESULT_POLL_SECONDS = 0.1
WORKER_RESULT_EXIT_GRACE_SECONDS = 1.0


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _ProcessMemoryCounters(ctypes.Structure):
        _fields_ = (
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        )

    def peak_rss_kib() -> int:
        """Return this process's peak working set size in KiB."""
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        ctypes.windll.psapi.GetProcessMemoryInfo(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        )
        return counters.PeakWorkingSetSize // 1024

else:
    import resource

    def peak_rss_kib() -> int:
        """Return this process's peak RSS as reported by getrusage.

        Linux reports ru_maxrss in KiB; macOS reports it in bytes.
        """
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak_rss // 1024 if sys.platform == "darwin" else peak_rss


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
