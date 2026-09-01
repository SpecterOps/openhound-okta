<p align="center">
  <a href="https://specterops.io" target="_blank">
    <img alt="A project powered by SpecterOps - Creators of BloodHound" src=".github/GitHub-Header.png" width="100%" style="max-width: 100%;">
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

[![Python Version](https://img.shields.io/badge/Python-3.13-brightgreen.svg)](#about)

## Getting Started

Follow the OpenHound docs to get started:

- [OpenHound Documentation](https://bloodhound.specterops.io/openhound/overview)

## OAuth app authentication behavior

When the collector uses Okta OAuth app credentials, it shares one bearer token across endpoint clients and refreshes
that token before it expires. Long-running collections can therefore continue across the Okta access-token lifetime
without failing active resource pagination. If a transient proactive refresh fails while the current token is still
valid, the collector temporarily keeps using that token and suppresses repeated refresh attempts for a short cooldown.
If Okta rejects a bearer token with HTTP 401, the collector retries once for stale, invalid, or unknown token responses
while preserving the current token for known non-token authorization failures. Classic SSWS API token authentication
remains static.

## Rate-limit behavior

The collector coordinates requests by Okta API endpoint family. It limits concurrent requests, observes
`X-Rate-Limit-Remaining` and `X-Rate-Limit-Reset` on successful responses, and paces later requests before a bucket
is exhausted. HTTP 429 responses retry the same request and pagination cursor until a bounded elapsed-time budget is
reached. Transport failures and HTTP 5xx responses retain DLT's retry coverage.

Fan-out resources use explicit page sizes where Okta documents safe maxima. Expanded group collection requests 200
rows per page, application-user collection requests 500 rows per page, group-push mapping collection requests 1,000
rows per page, and identity-provider user collection requests 200 rows per page. Rows stream to DLT; an exhausted
required request fails the collection so DLT does not publish an incomplete replacement.
If the initial expanded group page repeatedly times out, the collector retries that first page with successively halved
limits before failing. With the default configuration, that sequence is 200, 100, then 50.

The defaults can be adjusted with DLT source configuration environment variables:

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `SOURCES__SOURCE__OKTA__APPLICATION_USERS_PAGE_SIZE` | `500` | Application users per page, from 1 through 500 |
| `SOURCES__SOURCE__OKTA__GROUPS_PAGE_SIZE` | `200` | Expanded groups per page, from 1 through 200 |
| `SOURCES__SOURCE__OKTA__GROUP_PUSH_MAPPINGS_PAGE_SIZE` | `1000` | Group push mappings per page, from 1 through 1,000 |
| `SOURCES__SOURCE__OKTA__IDENTITY_PROVIDER_USERS_PAGE_SIZE` | `200` | Identity-provider users per page, from 1 through 200 |
| `SOURCES__SOURCE__OKTA__ENDPOINT_CONCURRENCY` | `2` | Maximum simultaneous requests per endpoint family |
| `SOURCES__SOURCE__OKTA__RATE_LIMIT_MAX_ELAPSED_SECONDS` | `900` | Maximum elapsed retry window for an individual 429 request |
| `SOURCES__SOURCE__OKTA__RATE_LIMIT_REMAINING_RESERVE` | `1` | Requests held in reserve when pacing against a rate-limit window |
