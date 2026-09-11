# Okta collection performance telemetry

Optional performance telemetry helps distinguish measured collection costs
without changing collection scope or scheduling. It aggregates existing Okta
requests only. It does not add provider calls, permissions, external exporters,
or DEBUG logging.

## Configure

Put every telemetry option in `.dlt/config.toml`:

```toml
[sources.source.okta.telemetry]
enabled = true
output_directory = "./telemetry"
reporting_interval_seconds = 60
max_file_bytes = 10485760
max_interval_records = 1440
queue_capacity = 16
```

| TOML key | Environment override | Default | Validation |
| --- | --- | ---: | --- |
| `enabled` | `SOURCES__SOURCE__OKTA__TELEMETRY__ENABLED` | `false` | Boolean |
| `output_directory` | `SOURCES__SOURCE__OKTA__TELEMETRY__OUTPUT_DIRECTORY` | `./telemetry` | Must be outside the raw collection output tree |
| `reporting_interval_seconds` | `SOURCES__SOURCE__OKTA__TELEMETRY__REPORTING_INTERVAL_SECONDS` | `60` | Greater than zero |
| `max_file_bytes` | `SOURCES__SOURCE__OKTA__TELEMETRY__MAX_FILE_BYTES` | `10485760` | At least 65,536 bytes |
| `max_interval_records` | `SOURCES__SOURCE__OKTA__TELEMETRY__MAX_INTERVAL_RECORDS` | `1440` | At least 1 |
| `queue_capacity` | `SOURCES__SOURCE__OKTA__TELEMETRY__QUEUE_CAPACITY` | `16` | At least 2 |

DLT environment values override `config.toml`; omitted values use the table
defaults. Credentials remain in `secrets.toml` and are never telemetry options.
To disable telemetry explicitly, set `enabled = false` or remove the telemetry
section. No artifact is written while disabled.

Run collection normally. The configuration is independent of the CLI entry
point, so the same file/env contract works for supported interactive,
scheduled, and container invocations:

```text
openhound collect okta /path/to/raw-output
```

The output directory receives one
`openhound-okta-<opaque-run-id>.jsonl` file per collection. Retrieve that file
directly; do not place it under `/path/to/raw-output` or include it in a
collection upload.

## Interpret

Every line is an independently parseable JSON record with `schema_version`,
`record_type`, and an opaque `run_id`.

- `run_start` is written first with `state: incomplete`. If the process is
  interrupted, this and already-flushed intervals remain useful evidence.
- `interval` contains a monotonic elapsed boundary, sample counts, rates, and
  bounded endpoint-template aggregates.
- `run_summary` separates `collection_state` from `telemetry_state`, then
  includes component versions,
  effective performance settings, application-stream outcomes, cumulative
  measurements, and exporter health.
- `export_status` reports file truncation when the byte budget is reached.

The effective performance settings also include DLT's extraction controls as
`extract_workers` and `extract_max_parallel_items`. Configure those controls in
the same `config.toml`, separately from the Okta endpoint-family limit:

```toml
[extract]
workers = 10
max_parallel_items = 40

[sources.source.okta]
endpoint_concurrency = 4
```

The latency groups have deliberately distinct meanings:

- `slot_wait` is time waiting for the collector endpoint-family concurrency
  semaphore.
- `proactive_pacing_wait` is time the limiter waits based on previously
  observed quota headers.
- `retry_backoff_wait` is actual wait before a retry. The separate
  `retry_delay_seconds` fields are scheduled delays by retry category.
- `http_execution` begins immediately before request execution and ends after
  response-body transfer. It excludes JSON decoding and downstream DLT row
  conversion.

Each distribution states its unit, sample count, sum, minimum, maximum, and
fixed histogram buckets. Summed waits are worker-time samples. Because workers
overlap, they must not be added together and presented as elapsed run-time
attribution. `pages_yielded` and `rows_yielded` mean the API paginator yielded
them; they do not prove that DLT committed a replacement load.

Quota observations report each allowlisted header as `valid`, `missing`, or
`invalid`; reset timing is also marked `current`, `stale`, or `unavailable`.
The recorded limiter group is a collector implementation grouping. The
collector does not claim it is the identity of an Okta provider bucket. Zero
HTTP 429 responses does not imply unused quota: proactive pacing, another
client, or an unobserved provider limit may still consume or constrain it.

A shortened example is:

```json
{"schema_version":"1.0","record_type":"run_start","run_id":"opaque","state":"incomplete"}
{"schema_version":"1.0","record_type":"interval","run_id":"opaque","sequence":1,"interval":{"start_elapsed_seconds":0.0,"end_elapsed_seconds":60.0,"elapsed_seconds":60.0},"endpoints":{"/api/v1/apps/{app}/users":{"attempts":120,"pages_yielded":118,"rows_yielded":59000,"max_observed_concurrency":2}}}
{"schema_version":"1.0","record_type":"run_summary","run_id":"opaque","state":"complete","elapsed_seconds":3600.0,"application_streams":{"completed":200,"failed":0},"export":{"dropped_records":0,"output_truncated":false,"exporter_error":false}}
```

Actual records include the complete bounded measurement objects; the example
omits fields only to stay readable.

## Data boundary

The artifact allowlists numeric quotas, durations, counts, effective numeric
performance settings, fixed error categories, and normalized endpoint
templates. It excludes authorization data, cookies, tenant hostnames, raw URLs,
queries and cursors, object identifiers, profiles, application settings, SAML
values, response bodies, and exception text. Application streams are aggregated
as counts; no application-level correlation identifier is emitted.

## Troubleshoot output

An unwritable/full destination or writer failure logs only a value-free
`error_category`. It does not fail collection, suppress yielded rows, or alter
request/retry decisions. Correct the directory ownership or free space, then
run another collection. A failed exporter may leave only the records flushed
before the failure; do not interpret absence of a complete summary as a
successful collection.

`dropped_records`, `output_truncated`, or `exporter_error` in the summary means
the diagnostic is incomplete even when collection completed. Increase the
applicable `config.toml` bound or choose a healthy local destination before the
next run. Aggregation state is fixed by the normalized endpoint set and latency
histograms; it does not grow with total request count.

## Benchmark procedure

Performance acceptance uses identical deterministic replay inputs and worker
settings for telemetry off/on. Run at least five repetitions of each mode on
the same machine. The representative workload must include many applications
and at least one stream totaling one million assignments at the configured page
size. Record wall time, process CPU, peak RSS, and diagnostic bytes for every
run, then compare medians. The acceptance limit is no more than 5% added median
collection time. Replay evidence does not predict a customer speedup and does
not establish a tenant's available Okta quota.

### 2026-09-11 local replay result

Command:

```text
PYTHONPATH=src RUNTIME__LOG_PATH=/tmp/openhound-okta-bed-9741-logs .venv/bin/python tools/benchmark_telemetry.py
```

The test host ran Linux 6.8.12 on an AMD EPYC-Rome processor with Python
3.13.13. Each mode replayed 200 applications, 10 pages per application, 500
rows per page, and a deliberately small 2 ms HTTP delay: 2,000 requests and one
million yielded assignments per repetition. Every repetition/mode ran in a
fresh subprocess so peak RSS is a per-run high-water mark.

| Repetition | Off wall (s) | On wall (s) | Off CPU (s) | On CPU (s) | Off peak RSS (KiB) | On peak RSS (KiB) | Artifact (bytes) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 4.187751 | 4.350862 | 0.048764 | 0.212125 | 28,800 | 29,376 | 5,393 |
| 2 | 4.191242 | 4.386274 | 0.049671 | 0.232235 | 28,800 | 28,800 | 5,394 |
| 3 | 4.209063 | 4.406338 | 0.058257 | 0.230379 | 28,800 | 28,800 | 5,395 |
| 4 | 4.200649 | 4.373644 | 0.055155 | 0.213087 | 28,800 | 28,800 | 5,395 |
| 5 | 4.209338 | 4.462982 | 0.055717 | 0.212818 | 28,800 | 28,800 | 5,392 |
| **Median** | **4.200649** | **4.386274** | **0.055155** | **0.213087** | **28,800** | **28,800** | **5,394** |

The enabled median wall time was 4.42% higher, within the 5% acceptance limit.
Median peak RSS did not increase at KiB resolution. The artifact remained a
fixed three-record start/interval/summary
shape for the one-million-row run; the implementation retains counters and
fixed histograms rather than per-request samples. This is a controlled local
replay result, not a customer timing result or a speedup prediction.
