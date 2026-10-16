<p align="center">
  <a href="https://specterops.io" target="_blank">
    <img alt="A project powered by SpecterOps - Creators of BloodHound" src="https://raw.githubusercontent.com/SpecterOps/OpenHound/refs/heads/main/.github/GitHub-Header.png" width="100%" style="max-width: 100%;">
  </a>
</p>

<h4 align="center">
  Okta collector for OpenHound
</h4>

<!-- Standard shields, please do not remove -->
<p align="center">
  <a href="https://slack.specterops.io"><img src="https://custom-icon-badges.demolab.com/badge/Slack-BloodHound%20Gang-4A154B?logo=slack&logoColor=fff" alt="Slack"/></a>
  <a href="https://reddit.com/r/SpecterOpsCommunity"><img src="https://img.shields.io/badge/Reddit-r/SpecterOpsCommunity-FF4500?logo=reddit&logoColor=white" alt="SpecterOps on Reddit"/></a>
  <a href="https://github.com/specterops"><img src="https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fspecterops%2F.github%2Fmain%2Fconfig%2Fshield.json&style=flat" alt="Sponsored by SpecterOps"/></a>
</p>


<p align="center">
  <a href="https://x.com/SpecterOps"><img src="https://img.shields.io/twitter/follow/SpecterOps?style=social" alt="@SpecterOps on Twitter"/></a>
  <a href="https://www.linkedin.com/company/specterops/"><img src="https://custom-icon-badges.demolab.com/badge/LinkedIn-0A66C2?logo=linkedin-white&logoColor=fff" alt="Connect on LinkedIn"/></a>
  <a href="https://infosec.exchange/@specterops"><img src="https://img.shields.io/mastodon/follow/109314317500800201?domain=https%3A%2F%2Finfosec.exchange&style=social" alt="Connect on Mastodon"/></a>
</p>

---

## About

OpenHound is a standardized framework for building and running OpenGraph collectors and converters. It is built in
Python and powered by the [Data Load Tool (DLT)](https://dlthub.com/docs/intro) library, giving you a consistent
workflow to collect, process, and convert data from any source into BloodHound-compatible graphs.

The openhound-okta extension collects Okta resources and transforms these into usable nodes and edges for
BloodHound.

For SAML catalog integrations, see the [OIN route evidence and resolver
contract](docs/saml-oin-route-evidence.md). The collector prefers explicit
deployed routes and otherwise fails closed unless a reviewed catalog resolver
has the complete settings it requires.

## Trusted SAML issuer identity

Inbound trusted SAML issuer object IDs are scoped by the collecting Okta tenant
domain and the issuer's byte-exact entity ID. Multiple inbound identity
providers in one Okta tenant that trust the same issuer therefore share one
`SAML_Issuer` node, while identical entity IDs observed in different Okta
tenants remain separate. The entity ID remains available as the semantic value
for cross-collector correlation.

The shared-issuer ID change is additive in BloodHound. Existing IdP-keyed issuer
nodes and trust edges are not removed immediately by an upload; they age out
under the instance's normal retention behavior. Operators testing this change
may purge their BloodHound instance when a clean graph is needed.

[![Python Version](https://img.shields.io/badge/Python-3.13-brightgreen.svg)](#about)

## Getting Started

Follow the OpenHound docs to get started:

- [OpenHound Documentation](https://bloodhound.specterops.io/openhound/overview)

## Docker Compose

Run the BHE scheduler using the [Docker Compose deployment guide](docker-compose/README.md).
Release images are published to `ghcr.io/specterops/openhound-okta` for Linux AMD64 and ARM64,
with scheduler tags `<version>` and `latest`, and CLI tags `<version>-cli` and `latest-cli`.

## Authentication

The collector supports three Okta authentication methods. Configure exactly one of them in `.dlt/secrets.toml` or
through the equivalent environment variables.

### Private key (JWT) authentication

An OAuth 2.0 service app whose client authentication is set to public key / private key.
The private key is a JWK in JSON form, supplied either as a file path or base64-encoded:

```toml
[sources.source.okta.credentials]
base_url = "https://<tenant>.okta.com"
client_id = "<client-id>"
private_key_path = "<path-to-jwk.json>"
# Or, instead of private_key_path:
# private_key_b64 = "<base64-encoded-jwk-json>"
```

For environment-only deployments, use the equivalent variables:

```text
SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL=https://<tenant>.okta.com
SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_ID=<client-id>
SOURCES__SOURCE__OKTA__CREDENTIALS__PRIVATE_KEY_PATH=<path-to-jwk.json>
# Or, instead of PRIVATE_KEY_PATH:
# SOURCES__SOURCE__OKTA__CREDENTIALS__PRIVATE_KEY_B64=<base64-encoded-jwk-json>
```

### Client secret authentication

A service app whose client authentication is set to client secret, or an Okta Integration Network (OIN) API Service
Integration:

```toml
[sources.source.okta.credentials]
base_url = "https://<tenant>.okta.com"
client_id = "<client-id>"
client_secret = "<client-secret>"
```

For environment-only deployments, use the equivalent variables:

```text
SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL=https://<tenant>.okta.com
SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_ID=<client-id>
SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_SECRET=<client-secret>
```

### API token (SSWS) authentication

A classic API token, also called an SSWS token. Such tokens are user-specific and act with the permissions of the
administrator they were issued to:

```toml
[sources.source.okta.credentials]
base_url = "https://<tenant>.okta.com"
token = "<api-token>"
```

For environment-only deployments, use the equivalent variables:

```text
SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL=https://<tenant>.okta.com
SOURCES__SOURCE__OKTA__CREDENTIALS__TOKEN=<api-token>
```

### Bearer token lifecycle

With private key or client secret authentication, the collector uses the respective secret to fetch an OAuth 2.0
bearer token and refreshes that token before it expires, so long-running collections continue across the Okta access
token lifetime. If a refresh fails while the current token is
still valid, the collector keeps using that token and retries the refresh after a short cooldown. If Okta rejects a
bearer token, the collector retries the request with a fresh token, unless the response shows the
failure is unrelated to the token.

## Rate-limit behavior

The collector coordinates requests by Okta API endpoint family. Families are aligned one-to-one with the Okta
rate-limit buckets observed for the collector's endpoints (per-user reads, the users listing, groups, apps, IAM,
devices, OAuth clients, API service integrations, and the `/api/v1` catch-all); the per-minute limits of those
buckets differ by org tier. It limits concurrent requests, observes
`X-Rate-Limit-Remaining` and `X-Rate-Limit-Reset` on successful responses, and paces later requests before a bucket
is exhausted. HTTP 429 responses retry the same request and pagination cursor until a bounded elapsed-time budget is
reached. HTTP 5xx responses and transport failures pause every endpoint family org-wide before the request is
retried.

Fan-out resources use explicit page sizes where Okta documents safe maxima. Expanded group collection requests 200
rows per page, application-user collection requests 500 rows per page, application-group assignment collection
requests 200 rows per page, group-push mapping collection requests 1,000 rows per page, and identity-provider user
collection requests 200 rows per page. MFA factor collection costs one request per covered user; in large
organizations it can be restricted to privileged users with `limit_user_mfa_collection`. Application-group
assignments are collected from each application's public
assignment endpoint and retain Okta's assignment timestamp, priority, and profile field names without publishing
assignment profile values to the graph. Rows stream to DLT; an exhausted required request fails the collection so DLT
does not publish an incomplete replacement. If the initial expanded group page repeatedly times out, the collector
retries that first page with successively halved limits before failing. With the default configuration, that sequence
is 200, 100, then 50.

The defaults can be adjusted in `.dlt/config.toml` under
`[sources.source.okta]`. DLT environment variables may override the same
non-secret settings:

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `SOURCES__SOURCE__OKTA__APPLICATIONS_PAGE_SIZE` | `200` | Applications per page, from 1 through 200 |
| `SOURCES__SOURCE__OKTA__APPLICATION_USERS_PAGE_SIZE` | `500` | Application users per page, from 1 through 500 |
| `SOURCES__SOURCE__OKTA__GROUPS_PAGE_SIZE` | `200` | Expanded groups per page, from 1 through 200 |
| `SOURCES__SOURCE__OKTA__APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE` | `200` | Application-group assignments per page, from 20 through 200 |
| `SOURCES__SOURCE__OKTA__GROUP_PUSH_MAPPINGS_PAGE_SIZE` | `1000` | Group push mappings per page, from 1 through 1,000 |
| `SOURCES__SOURCE__OKTA__IDENTITY_PROVIDER_USERS_PAGE_SIZE` | `200` | Identity-provider users per page, from 1 through 200 |
| `SOURCES__SOURCE__OKTA__LIMIT_USER_MFA_COLLECTION` | `false` | Collect MFA factors only for privileged users (direct role assignees and admin-group members) instead of every user; factor collection costs one request per covered user |
| `SOURCES__SOURCE__OKTA__ENDPOINT_CONCURRENCY` | `32` | Maximum simultaneous requests per endpoint family |
| `SOURCES__SOURCE__OKTA__ORG_CONCURRENCY` | `32` | Maximum simultaneous requests across all endpoint families, kept under Okta's per-org concurrency limit (35 on Integrator Free, 75 on production orgs) |
| `SOURCES__SOURCE__OKTA__RATE_LIMIT_MAX_ELAPSED_SECONDS` | `900` | Maximum elapsed retry window for an individual 429 request |
| `SOURCES__SOURCE__OKTA__RATE_LIMIT_REMAINING_RESERVE` | `1` | Requests held in reserve when pacing against a rate-limit window |

## Optional collection performance telemetry

Collection telemetry is disabled by default. When enabled in `config.toml`, it
writes bounded, value-free JSONL diagnostics to a local directory without
requiring DEBUG logging, an external service, an additional Okta permission, or
an additional request. The same configuration applies to interactive,
scheduled, and containerized `openhound collect okta` invocations.

```toml
[sources.source.okta.telemetry]
enabled = true
output_directory = "./telemetry"
reporting_interval_seconds = 60
max_file_bytes = 10485760
max_interval_records = 1440
queue_capacity = 16
```

Keep `output_directory` outside the collection raw-data directory. The
collector rejects an unsafe nested telemetry location so diagnostics cannot be
discovered, converted, or uploaded as Okta collection data. Each collection
creates `openhound-okta-<opaque-run-id>.jsonl`; disabling telemetry creates no
artifact.

Environment variables use the equivalent nested DLT names, such as
`SOURCES__SOURCE__OKTA__TELEMETRY__ENABLED=true` and
`SOURCES__SOURCE__OKTA__TELEMETRY__OUTPUT_DIRECTORY=/diagnostics`. Environment
values take precedence over `config.toml`; omitted values use the defaults
shown above. Reporting intervals must be positive, `max_file_bytes` must be at
least 65,536, `max_interval_records` must be at least 1, and `queue_capacity`
must be at least 2.

The artifact separates concurrency-slot waits, proactive pacing, retry
backoff, and HTTP execution. HTTP execution includes response-body transfer but
not JSON decoding or downstream row conversion. Wait distributions are summed
worker samples, not additive wall-clock attribution. Pages and rows are API
yield progress and do not mean DLT committed the output. Collector endpoint
families mirror Okta's bucket layout as observed in one org; they are not verified against the provider at runtime. In particular,
zero HTTP 429 responses does not prove that quota was unused.

The summary records DLT's effective `extract_workers` and
`extract_max_parallel_items` values as well as the Okta settings above. Put
shared worker tuning under `[extract]` in the same `config.toml`, or use
`[sources.source.okta.extract]` when the override is intentionally scoped to
this source. The reported values use DLT's source-scoped resolution and include
the values from whichever TOML scope wins. Do not use telemetry artifacts from
different settings as direct performance pairs.

The first record marks the run incomplete, periodic interval records retain
useful progress after interruption, and a normal end adds a concise complete
summary. Output truncation, dropped records, and exporter failure are explicit
and value-free. A telemetry write failure is logged but never changes request,
retry, or collection failure behavior. See
[`docs/collection-performance-telemetry.md`](docs/collection-performance-telemetry.md)
for the record contract, interpretation, troubleshooting, representative
collection benchmark, and separate recorder microbenchmark.
