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

[sources.source.okta.extract]
# Optional Okta-only override of the shared [extract] values.
workers = 10
max_parallel_items = 40

[sources.source.okta]
endpoint_concurrency = 4
```

DLT resolves the source-scoped extraction table over the shared extraction
table. Telemetry uses DLT's own extraction configuration spec under the Okta
source context, so the reported values match the worker pool rather than a
separate set of hardcoded defaults.

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

## Collection benchmark procedure

Performance acceptance uses identical deterministic replay inputs and worker
settings for telemetry off/on. Run at least five repetitions of each mode on
the same machine. The representative workload must include many applications
and at least one stream totaling one million assignments at the configured page
size. Record wall time, process CPU, peak RSS, and diagnostic bytes for every
run, then compare medians. The acceptance limit is no more than 5% added median
collection time. Replay evidence does not predict a customer speedup and does
not establish a tenant's available Okta quota.

Run the representative replay with:

```text
PYTHONPATH=src RUNTIME__LOG_PATH=/tmp/openhound-okta-bed-9741-logs .venv/bin/python tools/benchmark_collection_telemetry.py
```

It generates paginated Okta-shaped HTTP responses through `OktaRESTClient`,
streams those responses through `application_user_rows`, extracts the validated
`ApplicationUser` resource with DLT, and converts the raw collection with the
OpenHound converter. Each off/on pair must have the same order-independent
graph digest and cardinality. The default workload performs five repetitions
per mode over 200 applications and one million assignments.

