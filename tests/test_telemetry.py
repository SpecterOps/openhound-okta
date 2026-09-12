import json
import threading
from pathlib import Path

import pytest
import requests
from dlt.common.configuration.container import Container
from dlt.common.configuration.specs.pluggable_run_context import PluggableRunContext
from dlt.sources.helpers.requests.session import Session
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator
from openhound.core.app import Contract
from openhound.core.collect import Collector
from openhound.core.progress import Progress
from requests import Request
from requests.adapters import BaseAdapter

from openhound_okta import main
from openhound_okta.telemetry import (
    LatencyDistribution,
    MIN_MAX_FILE_BYTES,
    TelemetryRecorder,
    TelemetrySettings,
    build_telemetry,
    normalize_endpoint_template,
)
from openhound_okta.utils.http import EndpointThrottle, OktaRESTClient


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_telemetry_is_disabled_by_default_and_writes_nothing(tmp_path):
    recorder = build_telemetry(TelemetrySettings(), collection_output=tmp_path / "raw")

    recorder.record_page("/api/v1/apps/private/users?after=secret", 1)
    recorder.finish("complete")

    assert recorder.active is False
    assert list(tmp_path.rglob("*.jsonl")) == []


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"reporting_interval_seconds": 0}, "reporting_interval_seconds"),
        ({"reporting_interval_seconds": float("nan")}, "reporting_interval_seconds"),
        ({"reporting_interval_seconds": float("inf")}, "reporting_interval_seconds"),
        ({"reporting_interval_seconds": float("-inf")}, "reporting_interval_seconds"),
        ({"max_file_bytes": MIN_MAX_FILE_BYTES - 1}, "max_file_bytes"),
        ({"max_interval_records": 0}, "max_interval_records"),
        ({"queue_capacity": 1}, "queue_capacity"),
    ],
)
def test_telemetry_settings_reject_invalid_limits(values, message):
    with pytest.raises(ValueError, match=message):
        TelemetrySettings.from_mapping(values)


def test_latency_merge_preserves_zero_minimum():
    aggregate = LatencyDistribution()
    first = LatencyDistribution()
    first.observe(1.0)
    second = LatencyDistribution()
    second.observe(0.0)

    aggregate.merge(first)
    aggregate.merge(second)

    assert aggregate.minimum_seconds == 0.0
    assert aggregate.maximum_seconds == 1.0


def test_config_toml_settings_are_loaded_from_the_okta_telemetry_section(
    monkeypatch, tmp_path
):
    values = {
        "sources.source.okta.telemetry.enabled": True,
        "sources.source.okta.telemetry.output_directory": str(tmp_path),
        "sources.source.okta.telemetry.reporting_interval_seconds": 30.0,
        "sources.source.okta.telemetry.max_file_bytes": 131_072,
        "sources.source.okta.telemetry.max_interval_records": 4,
        "sources.source.okta.telemetry.queue_capacity": 8,
    }
    requested = []

    def get_config(key, expected_type):
        requested.append((key, expected_type))
        return values.get(key)

    monkeypatch.setattr(main.dlt.config, "get", get_config)

    settings = main._telemetry_settings_from_config()

    assert settings == TelemetrySettings(
        enabled=True,
        output_directory=tmp_path,
        reporting_interval_seconds=30.0,
        max_file_bytes=131_072,
        max_interval_records=4,
        queue_capacity=8,
    )
    assert {key for key, _ in requested} == set(values)


def test_extract_performance_settings_use_source_scoped_config_toml(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("SOURCES__SOURCE__OKTA__EXTRACT__WORKERS", raising=False)
    monkeypatch.delenv(
        "SOURCES__SOURCE__OKTA__EXTRACT__MAX_PARALLEL_ITEMS", raising=False
    )
    settings_directory = tmp_path / ".dlt"
    settings_directory.mkdir()
    (settings_directory / "config.toml").write_text(
        """
[sources.source.okta.extract]
workers = 6
max_parallel_items = 22
""".strip()
    )
    run_context = Container()[PluggableRunContext]
    cookie = run_context.push_context()
    try:
        run_context.reload(str(tmp_path))
        from openhound_okta.source import OktaTokenCredentials, source

        source_object = source(
            credentials=OktaTokenCredentials(
                base_url="https://example.okta.test",
                token="not-used",
            )
        )
        settings = main._extract_performance_settings_from_source(source_object)
    finally:
        run_context.pop_context(cookie)

    assert settings == {
        "extract_workers": 6,
        "extract_max_parallel_items": 22,
    }


def test_extract_performance_settings_use_dlt_source_scoped_environment_overrides(
    monkeypatch, tmp_path
):
    settings_directory = tmp_path / ".dlt"
    settings_directory.mkdir()
    (settings_directory / "config.toml").write_text(
        """
[sources.source.okta.extract]
workers = 6
max_parallel_items = 22
""".strip()
    )
    monkeypatch.setenv("SOURCES__SOURCE__OKTA__EXTRACT__WORKERS", "9")
    monkeypatch.setenv(
        "SOURCES__SOURCE__OKTA__EXTRACT__MAX_PARALLEL_ITEMS", "27"
    )
    run_context = Container()[PluggableRunContext]
    cookie = run_context.push_context()
    try:
        run_context.reload(str(tmp_path))
        from openhound_okta.source import OktaTokenCredentials, source

        source_object = source(
            credentials=OktaTokenCredentials(
                base_url="https://example.okta.test",
                token="not-used",
            )
        )
        settings = main._extract_performance_settings_from_source(source_object)
    finally:
        run_context.pop_context(cookie)

    assert settings == {
        "extract_workers": 9,
        "extract_max_parallel_items": 27,
    }


def test_environment_overrides_config_toml(monkeypatch, tmp_path):
    settings_directory = tmp_path / ".dlt"
    settings_directory.mkdir()
    (settings_directory / "config.toml").write_text(
        """
[sources.source.okta.telemetry]
enabled = true
output_directory = "./from-config"
reporting_interval_seconds = 60
max_file_bytes = 131072
max_interval_records = 12
queue_capacity = 8
""".strip()
    )
    monkeypatch.setenv(
        "SOURCES__SOURCE__OKTA__TELEMETRY__REPORTING_INTERVAL_SECONDS", "30"
    )
    run_context = Container()[PluggableRunContext]
    cookie = run_context.push_context()
    try:
        run_context.reload(str(tmp_path))
        settings = main._telemetry_settings_from_config()
    finally:
        run_context.pop_context(cookie)

    assert settings.enabled is True
    assert settings.output_directory == Path("./from-config")
    assert settings.reporting_interval_seconds == 30.0
    assert settings.max_file_bytes == 131_072


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://tenant.example/api/v1/apps/0oa-private/users?after=cursor-secret",
            "/api/v1/apps/{app}/users",
        ),
        (
            "/api/v1/apps/0oa-private/groups",
            "/api/v1/apps/{app}/groups",
        ),
        ("https://tenant.example/private/value", "other"),
    ],
)
def test_endpoint_templates_exclude_hosts_queries_and_ids(url, expected):
    assert normalize_endpoint_template(url) == expected


def test_enabled_telemetry_writes_value_free_interval_and_summary(tmp_path):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": True,
            "output_directory": tmp_path / "diagnostics",
            "reporting_interval_seconds": 60,
        }
    )
    recorder = TelemetryRecorder(settings, collection_output=tmp_path / "raw")
    sensitive_url = (
        "https://tenant-secret.example/api/v1/apps/0oa-private/users"
        "?after=cursor-secret"
    )
    recorder.set_effective_settings({"extract_workers": 5})
    recorder.set_effective_settings({"endpoint_concurrency": 2})
    recorder.record_throttle_wait(
        sensitive_url,
        slot_wait_seconds=0.25,
        pacing_wait_seconds=0.5,
        retry_backoff_wait_seconds=1.0,
        queue_depth=2,
        observed_concurrency=2,
    )
    recorder.record_http_response(
        sensitive_url,
        status_code=429,
        duration_seconds=0.75,
        headers={
            "X-Rate-Limit-Limit": "100",
            "X-Rate-Limit-Remaining": "0",
            "X-Rate-Limit-Reset": "bad-secret-value",
            "Retry-After": "2",
            "Set-Cookie": "cookie-secret",
        },
    )
    recorder.record_retry(sensitive_url, category="rate_limit", delay_seconds=2.0)
    recorder.record_page(sensitive_url, 500)
    recorder.record_application_stream("completed")
    recorder.record_transport_error(
        sensitive_url,
        error=requests.ConnectionError("exception-secret"),
        duration_seconds=0.1,
    )
    recorder.finish("complete")

    records = _records(recorder.artifact_path)
    assert [record["record_type"] for record in records] == [
        "run_start",
        "interval",
        "run_summary",
    ]
    summary = records[-1]
    metrics = summary["endpoints"]["/api/v1/apps/{app}/users"]
    assert summary["state"] == "complete"
    assert summary["telemetry_state"] == "complete"
    assert summary["effective_performance_settings"] == {
        "endpoint_concurrency": 2,
        "extract_workers": 5,
    }
    assert summary["effective_telemetry_settings"] == {
        "reporting_interval_seconds": 60.0,
        "max_file_bytes": 10_485_760,
        "max_interval_records": 1_440,
        "queue_capacity": 16,
    }
    assert summary["application_streams"] == {"completed": 1}
    assert metrics["attempts"] == 2
    assert metrics["outcomes"] == {
        "rate_limited": 1,
        "transport_error": 1,
    }
    assert metrics["rows_yielded"] == 500
    assert metrics["latest_quota_observation"]["headers"]["reset_epoch_seconds"] == {
        "state": "invalid",
        "value": None,
    }
    artifact = recorder.artifact_path.read_text()
    for sensitive_value in (
        "tenant-secret",
        "0oa-private",
        "cursor-secret",
        "cookie-secret",
        "bad-secret-value",
        "exception-secret",
    ):
        assert sensitive_value not in artifact


def test_application_stream_only_interval_is_retained(tmp_path):
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
    )

    recorder.record_application_stream("completed")
    recorder.finish("complete")

    records = _records(recorder.artifact_path)
    interval = next(record for record in records if record["record_type"] == "interval")
    assert interval["application_streams"] == {"completed": 1}
    assert records[-1]["application_streams"] == {"completed": 1}


def test_telemetry_output_inside_collection_data_is_rejected(tmp_path, caplog):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": True,
            "output_directory": tmp_path / "raw" / "telemetry",
        }
    )

    recorder = TelemetryRecorder(settings, collection_output=tmp_path / "raw")
    recorder.finish("complete")

    assert not recorder.artifact_path.exists()
    assert "unsafe_output_location" in caplog.text


def test_exporter_failure_does_not_raise_or_expose_destination(tmp_path, caplog):
    not_a_directory = tmp_path / "blocked"
    not_a_directory.write_text("occupied")
    settings = TelemetrySettings.from_mapping(
        {"enabled": True, "output_directory": not_a_directory / "child"}
    )

    recorder = TelemetryRecorder(settings, collection_output=tmp_path / "raw")
    recorder.record_page("/api/v1/users", 1)
    recorder.finish("incomplete", OSError("destination-secret"))

    assert "exporter_failure" in caplog.text
    assert "destination-secret" not in caplog.text
    assert str(not_a_directory) not in caplog.text


def test_quota_headers_report_missing_invalid_stale_and_http_date(tmp_path):
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
        monotonic=lambda: 0.0,
        wall_clock=lambda: 1_000.0,
    )
    recorder.record_http_response(
        "/api/v1/users",
        status_code=429,
        duration_seconds=0.1,
        headers={
            "X-Rate-Limit-Remaining": "not-a-number",
            "X-Rate-Limit-Reset": "900",
            "Retry-After": "Thu, 01 Jan 1970 00:20:00 GMT",
        },
    )
    recorder.finish("complete")

    quota = _records(recorder.artifact_path)[-1]["endpoints"]["/api/v1/users"][
        "latest_quota_observation"
    ]
    assert quota["state"] == "stale"
    assert quota["reset_freshness_seconds"] == -100.0
    assert quota["headers"] == {
        "limit": {"state": "missing", "value": None},
        "remaining": {"state": "invalid", "value": None},
        "reset_epoch_seconds": {"state": "valid", "value": 900.0},
        "retry_after_seconds": {"state": "valid", "value": 200.0},
    }


@pytest.mark.parametrize("non_finite", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_quota_headers_are_invalid_strict_json(tmp_path, non_finite):
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
        monotonic=lambda: 0.0,
        wall_clock=lambda: 1_000.0,
    )
    recorder.record_http_response(
        "/api/v1/users",
        status_code=429,
        duration_seconds=0.1,
        headers={
            "X-Rate-Limit-Reset": non_finite,
            "Retry-After": non_finite,
        },
    )
    recorder.finish("complete")

    lines = recorder.artifact_path.read_text().splitlines()
    records = [
        json.loads(
            line,
            parse_constant=lambda value: pytest.fail(
                f"non-standard JSON number: {value}"
            ),
        )
        for line in lines
    ]
    quota = records[-1]["endpoints"]["/api/v1/users"]["latest_quota_observation"]
    assert quota["state"] == "unavailable"
    assert quota["reset_freshness_seconds"] is None
    assert quota["headers"]["reset_epoch_seconds"] == {
        "state": "invalid",
        "value": None,
    }
    assert quota["headers"]["retry_after_seconds"] == {
        "state": "invalid",
        "value": None,
    }


def test_exporter_rejects_non_standard_json_numbers(tmp_path, caplog):
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
    )
    recorder.set_effective_settings({"invalid_test_value": float("nan")})

    recorder.finish("complete")

    for line in recorder.artifact_path.read_text().splitlines():
        json.loads(
            line,
            parse_constant=lambda value: pytest.fail(
                f"non-standard JSON number: {value}"
            ),
        )
    assert "exporter_failure" in caplog.text


def test_writer_uses_literal_lf_without_newline_translation(
    monkeypatch, tmp_path
):
    import os

    open_calls = []

    def open_file(*args, **kwargs):
        open_calls.append(kwargs)
        return open(*args, **kwargs)

    monkeypatch.setattr(os, "linesep", "\r\n")
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
        open_file=open_file,
    )
    recorder.record_page("/api/v1/users", 1)
    recorder.finish("complete")

    artifact = recorder.artifact_path.read_bytes()
    assert open_calls[0]["newline"] == ""
    assert artifact.endswith(b"\n")
    assert b"\r\n" not in artifact


def test_slow_writer_does_not_block_collection_measurements(tmp_path):
    writer_started = threading.Event()
    release_writer = threading.Event()

    class SlowFile:
        def write(self, value):
            writer_started.set()
            release_writer.wait(2.0)
            return len(value)

        def flush(self):
            pass

        def close(self):
            pass

    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {
                "enabled": True,
                "output_directory": tmp_path / "diagnostics",
                "queue_capacity": 2,
            }
        ),
        collection_output=tmp_path / "raw",
        open_file=lambda *args, **kwargs: SlowFile(),
    )
    assert writer_started.wait(1.0)
    measurements_finished = threading.Event()

    def record_measurements():
        for _ in range(20):
            recorder.record_page("/api/v1/users", 1)
            recorder.flush(force=True)
        measurements_finished.set()

    measurement_thread = threading.Thread(target=record_measurements)
    measurement_thread.start()
    assert measurements_finished.wait(0.5)
    assert recorder._dropped_records > 0
    release_writer.set()
    measurement_thread.join(timeout=1.0)
    recorder.finish("complete")


def test_interval_record_limit_is_explicit_in_summary(tmp_path):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": True,
            "output_directory": tmp_path / "diagnostics",
            "max_interval_records": 1,
        }
    )
    recorder = TelemetryRecorder(settings, collection_output=tmp_path / "raw")
    recorder.record_page("/api/v1/users", 1)
    recorder.flush(force=True)
    recorder.record_page("/api/v1/users", 1)
    recorder.flush(force=True)
    recorder.finish("complete")

    records = _records(recorder.artifact_path)
    intervals = [r for r in records if r["record_type"] == "interval"]
    summary = next(r for r in records if r["record_type"] == "run_summary")
    assert len(intervals) == 1
    assert summary["export"]["output_truncated"] is True
    assert summary["telemetry_state"] == "incomplete"
    assert summary["export"]["dropped_records"] == 1
    assert summary["endpoints"]["/api/v1/users"]["rows_yielded"] == 2


def test_file_size_limit_keeps_an_explicit_incomplete_summary(tmp_path):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": True,
            "output_directory": tmp_path / "diagnostics",
            "max_file_bytes": MIN_MAX_FILE_BYTES,
            "max_interval_records": 1_000,
            "queue_capacity": 256,
        }
    )
    recorder = TelemetryRecorder(settings, collection_output=tmp_path / "raw")
    for _ in range(100):
        recorder.record_http_response(
            "/api/v1/users",
            status_code=200,
            duration_seconds=0.1,
            headers={},
        )
        recorder.flush(force=True)
    recorder.finish("complete")

    assert recorder.artifact_path.stat().st_size <= MIN_MAX_FILE_BYTES
    records = _records(recorder.artifact_path)
    assert any(record["record_type"] == "export_status" for record in records)
    assert records[-1]["record_type"] == "run_summary"
    assert records[-1]["telemetry_state"] == "incomplete"
    assert records[-1]["export"]["output_truncated"] is True


class _FakeClock:
    def __init__(self):
        self.now = 1_000.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class _SequenceAdapter(BaseAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    def send(self, request, **kwargs):
        self.urls.append(request.url)
        response = self.responses.pop(0)
        response.request = request
        response.connection = self
        return response

    def close(self):
        pass


def _response(status, url, *, headers=None, content=b"[]"):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers.update(headers or {})
    response._content = content
    return response


def _replay_with_telemetry(tmp_path, enabled):
    first_url = "https://tenant.example/api/v1/apps/opaque/users?limit=500"
    cursor_url = f"{first_url}&after=opaque-cursor"
    adapter = _SequenceAdapter(
        [
            _response(
                200,
                first_url,
                headers={"Link": f'<{cursor_url}>; rel="next"'},
                content=b'[{"id":"first"}]',
            ),
            _response(429, cursor_url, headers={"Retry-After": "1"}),
            _response(200, cursor_url, content=b'[{"id":"second"}]'),
        ]
    )
    session = Session(raise_for_status=False)
    session.mount("https://", adapter)
    recorder = build_telemetry(
        TelemetrySettings.from_mapping(
            {
                "enabled": enabled,
                "output_directory": tmp_path / f"diagnostics-{enabled}",
            }
        ),
        collection_output=tmp_path / "raw",
    )
    clock = _FakeClock()
    client = OktaRESTClient(
        base_url="https://tenant.example",
        endpoint_family="/api/v1/apps*",
        throttle=EndpointThrottle(clock=clock.time, sleep=clock.sleep),
        paginator=HeaderLinkPaginator(),
        session=session,
        clock=clock.time,
        elapsed_clock=clock.time,
        sleep=clock.sleep,
        jitter=lambda: 0.0,
        telemetry=recorder,
    )
    rows = [
        item for page in client.paginate(Request("GET", first_url).url) for item in page
    ]
    recorder.finish("complete")
    return rows, adapter.urls, clock.sleeps, recorder


def test_enabled_telemetry_preserves_request_cursor_retry_and_rows(tmp_path):
    disabled = _replay_with_telemetry(tmp_path, False)
    enabled = _replay_with_telemetry(tmp_path, True)

    assert enabled[:3] == disabled[:3]
    assert enabled[0] == [{"id": "first"}, {"id": "second"}]
    assert enabled[2] == [1.0]
    summary = _records(enabled[3].artifact_path)[-1]
    metrics = summary["endpoints"]["/api/v1/apps/{app}/users"]
    assert metrics["attempts"] == 3
    assert metrics["outcomes"] == {"rate_limited": 1, "success": 2}
    assert metrics["retries"] == {"rate_limit": 1}
    assert metrics["collector_limiter_groups"] == ["/api/v1/apps*"]
    assert metrics["http_execution"]["quantile_upper_bounds_ms"]["p95"] == 1


def test_retained_measurement_state_is_independent_of_request_count(tmp_path):
    recorder = TelemetryRecorder(
        TelemetrySettings.from_mapping(
            {"enabled": True, "output_directory": tmp_path / "diagnostics"}
        ),
        collection_output=tmp_path / "raw",
    )

    for _ in range(10_000):
        recorder.record_page("/api/v1/apps/opaque/users", 500)

    assert len(recorder._interval) == 1
    measurements = recorder._interval["/api/v1/apps/{app}/users"]
    assert len(measurements.http_execution.buckets) == 14
    assert not hasattr(measurements, "samples")
    recorder.finish("complete")


@pytest.mark.parametrize(
    ("failure", "expected_state"), [(False, "complete"), (True, "incomplete")]
)
def test_collect_lifecycle_writes_terminal_summary(
    monkeypatch, tmp_path, failure, expected_state
):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": True,
            "output_directory": tmp_path / "diagnostics",
        }
    )
    monkeypatch.setattr(main, "_telemetry_settings_from_config", lambda: settings)
    monkeypatch.setattr(
        main,
        "_extract_performance_settings_from_source",
        lambda source: {
            "extract_workers": 5,
            "extract_max_parallel_items": 20,
        },
    )

    from openhound_okta import source as source_module

    monkeypatch.setattr(source_module, "source", lambda telemetry: object())

    def fake_run(self, source_object, **kwargs):
        if failure:
            raise RuntimeError("collection-secret")
        return "loaded"

    monkeypatch.setattr(Collector, "run", fake_run)

    if failure:
        with pytest.raises(RuntimeError, match="collection-secret"):
            main.collect(
                output_path=tmp_path / "raw",
                resources=[],
                progress=Progress.log,
                tables_contract=Contract.evolve,
                columns_contract=Contract.evolve,
                data_type_contract=Contract.discard_row,
            )
    else:
        assert (
            main.collect(
                output_path=tmp_path / "raw",
                resources=[],
                progress=Progress.log,
                tables_contract=Contract.evolve,
                columns_contract=Contract.evolve,
                data_type_contract=Contract.discard_row,
            )
            == "loaded"
        )

    artifact = next((tmp_path / "diagnostics").glob("*.jsonl"))
    summary = _records(artifact)[-1]
    assert summary["state"] == expected_state
    assert "collection-secret" not in artifact.read_text()


@pytest.mark.parametrize("enabled", [False, True])
def test_collect_settings_telemetry_cannot_fail_collection(
    monkeypatch, tmp_path, enabled
):
    settings = TelemetrySettings.from_mapping(
        {
            "enabled": enabled,
            "output_directory": tmp_path / "diagnostics",
        }
    )
    monkeypatch.setattr(main, "_telemetry_settings_from_config", lambda: settings)
    settings_calls = []

    def fail_settings(source):
        settings_calls.append(source)
        raise RuntimeError("settings-secret")

    monkeypatch.setattr(main, "_extract_performance_settings_from_source", fail_settings)

    from openhound_okta import source as source_module

    source_object = object()
    monkeypatch.setattr(source_module, "source", lambda telemetry: source_object)
    monkeypatch.setattr(Collector, "run", lambda self, source, **kwargs: "loaded")

    assert (
        main.collect(
            output_path=tmp_path / "raw",
            resources=[],
            progress=Progress.log,
            tables_contract=Contract.evolve,
            columns_contract=Contract.evolve,
            data_type_contract=Contract.discard_row,
        )
        == "loaded"
    )
    assert len(settings_calls) == int(enabled)
    if enabled:
        summary = _records(next((tmp_path / "diagnostics").glob("*.jsonl")))[-1]
        assert summary["collection_state"] == "complete"
        assert summary["effective_performance_settings"] == {}
    else:
        assert list((tmp_path / "diagnostics").glob("*.jsonl")) == []


def test_recorder_microbenchmark_worker_reports_errors(monkeypatch, tmp_path):
    from tools import benchmark_telemetry

    messages = []

    class Results:
        def put(self, message):
            messages.append(message)

    def fail_run_once(enabled, root, repetition):
        raise ValueError("benchmark failed")

    monkeypatch.setattr(benchmark_telemetry, "run_once", fail_run_once)

    with pytest.raises(ValueError, match="benchmark failed"):
        benchmark_telemetry._worker(True, tmp_path, 3, Results())

    assert messages == [
        {
            "error": "ValueError: benchmark failed",
            "enabled": True,
            "repetition": 3,
        }
    ]


def test_recorder_microbenchmark_isolated_run_surfaces_worker_error(
    monkeypatch, tmp_path
):
    from tools import benchmark_telemetry

    class Results:
        def get(self):
            return {
                "error": "ValueError: benchmark failed",
                "enabled": True,
                "repetition": 3,
            }

    class Process:
        exitcode = 1

        def start(self):
            pass

        def join(self):
            pass

    class Context:
        def Queue(self):
            return Results()

        def Process(self, **kwargs):
            return Process()

    monkeypatch.setattr(
        benchmark_telemetry.multiprocessing,
        "get_context",
        lambda method: Context(),
    )

    with pytest.raises(RuntimeError, match="ValueError: benchmark failed"):
        benchmark_telemetry.isolated_run(True, tmp_path, 3)


def test_representative_collection_replay_preserves_graph_parity(tmp_path):
    from tools.benchmark_collection_telemetry import run_once

    disabled = run_once(
        False,
        tmp_path,
        1,
        applications=2,
        assignments_per_application=4,
        rows_per_page=2,
    )
    enabled = run_once(
        True,
        tmp_path,
        1,
        applications=2,
        assignments_per_application=4,
        rows_per_page=2,
    )

    assert disabled["http_requests"] == enabled["http_requests"] == 4
    assert disabled["graph"] == enabled["graph"]
    assert enabled["graph"]["nodes"] == 0
    assert enabled["graph"]["edges"] == 8
    assert disabled["artifact_bytes"] == 0
    assert enabled["artifact_bytes"] > 0
    assert enabled["telemetry_summary"]["effective_performance_settings"] == {
        "extract_max_parallel_items": 20,
        "extract_workers": 5,
    }
