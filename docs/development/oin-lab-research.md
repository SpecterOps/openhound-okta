# Ephemeral OIN lab research

The OIN lab research harness creates short-lived, inactive Okta Integration
Network application instances to observe the source fields that Okta returns for
catalog integrations. It is development tooling owned by `openhound-okta`.

It is deliberately not part of the GlobalTech/KNG range model. The matrix in
`tools/oin_lab/matrix.sql` is SQL only to make experiments deterministic and
reviewable. It is not consumed by the GlobalTech DuckDB build, generated range
contracts, provisioners, deployment profiles, or range history.

## Safety contract

- Use only an operator-authorized disposable or lab Okta tenant.
- The default `create` and `capture` workflow creates apps with
  `POST /api/v1/apps?activate=false` and never assigns users or groups, enables
  provisioning, or configures a downstream service. The separately gated
  `active-trace` workflow is the only exception and is described below.
- Labels begin with `oin-lab-<run-id>-` and every created native app ID is
  recorded before the next experiment begins.
- Raw application JSON and SAML metadata stay under an external state directory
  with owner-only permissions. They are not fixtures and must not be committed.
- Review snapshots retain only `settings.app` and `settings.signOn`, remove
  credential-like fields, and replace the Okta tenant, application ID, and probe
  label with placeholders. A human must still review them before copying any
  finding into public documentation or a fixture.
- Cleanup re-reads every application and checks the recorded ID, exact label,
  exact catalog app key, and `INACTIVE` status. It refuses mismatches and verifies
  that a deleted app is absent.
- Live `create` and `cleanup` require explicit apply flags and exact tenant-host
  confirmation. Cleanup additionally requires the exact run ID.
- A failed or interrupted run is resumable by the same run ID. Do not reuse a run
  ID after cleanup; start a new run instead.
- Runs expire after 24 hours by default. Creation refuses an expired run while
  capture and cleanup remain available. `--max-age-hours` may set a reviewed
  value from 1 through 168 hours; it cannot extend an existing run.

The inactive cleanup command cannot deactivate an accidentally activated app. If
a probe app is activated outside the guarded active-trace lifecycle, cleanup
fails closed and an operator must review it in Okta before deletion.

## Matrix states

Each case has one of three readiness states:

- `ready`: public documentation identifies a supported creation schema or input
  contract. These cases are included in the default plan.
- `discovery`: public evidence is incomplete. Run only one explicitly selected
  case at a time with `--include-discovery`; an Okta validation error is useful
  evidence about required fields, but it is not a route contract.
- `blocked`: the integration requires authoritative downstream values, is not
  generally available in the lab plan, or must remain instance-defined. The
  harness refuses to create it.

The matrix covers all 44 public application families identified during the
research that introduced the harness. It also keeps the public Okta Businesses
at Work 2024-2026 report entries separate from their dated catalog mappings and
adds guarded discovery cases for each mapped SAML 2.0 candidate. Generated
custom integrations are intentionally absent. The harness and label namespace
are not tied to the tracking ticket so later Okta catalog refreshes can reuse
them.

Report names are not treated as catalog keys. One brand can map to multiple
product integrations, a non-SAML integration, or no current catalog entry. The
SQL records each of those outcomes rather than selecting a convenient route by
name. The current popularity dataset contains:

- the 50 most popular apps chart from the official
  [Businesses at Work 2024 report](https://www.okta.com/sites/default/files/2024-04/Okta-2024_Businesses_at_Work.pdf);
- the overall top 15 from Okta's official
  [Businesses at Work 2025 infographic](https://www.okta.com/sites/default/files/2025-03/Businesses-at-Work-Infographic.pdf)
  plus the growth apps named on the public report page; and
- the overall top 15 and fastest-growing 10 from the public
  [Okta Japan 2026 press release](https://www.okta.com/ja-jp/newsroom/press-releases/okta-businesses-at-work2026/)
  and its published chart assets. The full 2025 and 2026 reports are form-gated; the
  harness does not submit forms or attempt to bypass those gates.

## Offline planning

The following commands perform no network requests and require no token:

```bash
.venv/bin/python -m tools.oin_lab plan

.venv/bin/python -m tools.oin_lab plan \
  --run-id 20260813a \
  --case slack-workspace \
  --case zoom-single-vanity

.venv/bin/python -m tools.oin_lab create \
  --tenant-url https://lab.example.okta.com \
  --run-id 20260813a \
  --case slack-workspace
```

The last command is still an offline dry run because `--apply` is absent.

## Live creation and capture

Use a token dedicated to the lab operation with application read/manage access.
Do not put the token on the command line:

```bash
export OKTA_API_TOKEN='<lab token>'

.venv/bin/python -m tools.oin_lab create \
  --tenant-url https://lab.example.okta.com \
  --confirm-tenant-host lab.example.okta.com \
  --run-id 20260813a \
  --case slack-workspace \
  --case zoom-single-vanity \
  --apply
```

The default state root is
`$XDG_STATE_HOME/openhound-okta/oin-lab`, or
`~/.local/state/openhound-okta/oin-lab` when `XDG_STATE_HOME` is unset. Use
`--state-root` to choose another external location. The harness refuses any
state root inside the repository workspace, including `openhound-okta` and
GlobalTech.

To refresh raw and review captures without creating anything:

```bash
.venv/bin/python -m tools.oin_lab capture \
  --tenant-url https://lab.example.okta.com \
  --run-id 20260813a
```

Add `--include-metadata` when the Okta-generated IdP metadata is needed for
issuer comparison. That metadata describes Okta as IdP and must not be treated
as downstream ACS/entity evidence by itself. Okta can return `404` for metadata
on an inactive catalog app; the harness records it as unavailable and never
activates an app just to obtain metadata.

## Guarded active SAML trace

Some OIN integrations expose a computed ACS only after activation and an
IdP-initiated launch. `active-trace` is a deliberately narrow exception to the
inactive-app workflow. It accepts exactly one matrix case and performs one
transaction-like lifecycle:

1. create or resume one recorded, inactive `oin-lab-<run-id>-...` app;
2. refuse any app feature other than `AUTO_UPDATE_USERNAME` and refuse any
   existing assignment;
3. create one active, tenant-scoped `oin-lab-<run-id>-user@<tenant-host>` user
   with a random password, enroll one software-TOTP factor through Okta's
   Factors API, and hold both credential values only in process;
4. verify that the user has no admin roles, belongs only to built-in `Everyone`,
   inherits no group apps, and has no existing app links;
5. activate the app, directly assign exactly that user, and verify the app has
   exactly one assigned user;
6. launch the Okta app link in Playwright while allowing only the confirmed Okta
   tenant and non-navigation Okta CDN resources; the first outbound SAML request
   is parsed locally and aborted before delivery to the service provider; and
7. unassign and delete the user, deactivate and delete the app, and verify both
   objects are absent before returning.

The browser capture retains the outbound request URL and only SAML route fields:
message type, digest, Destination/Recipient, Audience, and Issuer. It does not
retain the assertion, NameID, attributes, password, TOTP seed, or RelayState
value. Raw and review observations remain in the external owner-only run
directory. A browser trace proves the route emitted by Okta for the synthetic
matrix variant; it does not prove a successful service-provider sign-in.

Install the optional browser dependency and Chromium before the first trace:

```bash
uv sync --group dev --group oin-lab
uv run playwright install chromium
```

Run a dry plan first. The live form requires exact tenant and run confirmation:

```bash
.venv/bin/python -m tools.oin_lab active-trace \
  --tenant-url https://lab.example.okta.com \
  --run-id 20260815-calibration \
  --case slack-workspace

.venv/bin/python -m tools.oin_lab active-trace \
  --tenant-url https://lab.example.okta.com \
  --confirm-tenant-host lab.example.okta.com \
  --run-id 20260815-calibration \
  --confirm-run-id 20260815-calibration \
  --case slack-workspace \
  --apply
```

The browser may answer only the software-TOTP challenge enrolled for that same
ephemeral user. Email, WebAuthn, push, or any other authentication challenge
fails closed and triggers cleanup; the harness never weakens tenant policy.

`active-trace` also wraps application creation and the initial inactive capture
in an outer cleanup boundary. A failure before browser tracing begins therefore
deletes an exact recorded inactive probe or records verified absence. If either
the app or a possibly created ephemeral user cannot be proven absent, the
command reports unverified cleanup and must halt any larger campaign.

After assignment, the harness allows bounded time for Okta app-link
propagation. Some catalog integrations expose several launch links for product
or service variants. The broad sweep records their count and labels, traces the
first Okta-ordered link, and leaves the remaining links for an explicit variant
sweep. An explicit recovery case can pin one previously observed dynamic label
suffix; that case fails cleanly if the exact link is no longer present. It
still fails closed if a link belongs to any other app, leaves the confirmed
Okta tenant, is malformed, or exceeds the bounded count.

The matrix may also pin a synthetic app-user assignment profile for an SSO-only
integration that requires one. These values must remain non-secret and must
not identify a real downstream account. They are passed only to the exact
temporary user's assignment and do not weaken the one-user or cleanup checks.

Routine case-specific failures such as a catalog integration requiring an
unset configuration value or producing no outbound SAML response are recorded
with a stable category and return normally after exact cleanup. Transport,
HTTP 401 authorization, rate limits, tenant-policy, identity-isolation, and
unknown failures remain campaign-scoped stops. Per-app 400, 403, and 404
responses are case-scoped because Okta catalog validation uses them for missing
integration settings as well as ordinary availability constraints.
`sweep-status`, not the trace process exit in isolation, is the authoritative
cleanup and continuation gate.

When an app-specific synthetic downstream hostname cannot resolve or refuses,
times out, aborts, or cannot accept navigation, active tracing records
`downstream_navigation_failed` as a clean case outcome after exact cleanup.
Browser launch failures, browser/context crashes, and unrecognized Playwright
errors remain campaign-scoped.

Before an active app is created, the harness reads its expanded catalog schema.
Required administrator-supplied ACS/entity/audience-style fields are evidence
that the integration is `explicit_only`; the case completes without creating
an app or user. Required non-route fields are filled with deterministic,
non-routable lab values when their primitive schema type is supported. The
external state records the schema disposition, field names, generation
strategies, and a settings digest, but does not turn synthetic values into route
evidence. This preparation applies only to `active-trace`; ordinary inactive
creation continues to use the checked-in matrix exactly.

Before delegating more than one trace, validate the browser, credential
plumbing, and authorized outbound access. This performs one read-only
Management API application lookup and creates no tenant object:

```bash
.venv/bin/python -m tools.oin_lab active-preflight \
  --tenant-url https://lab.example.okta.com \
  --state-root ~/.local/state/openhound-okta/oin-lab
```

Require both `management_api_read_verified: true` and
`browser_launch_verified: true` before consuming a campaign case. Agent
runtimes with restricted networking must obtain authorized outbound access to
the named tenant for this preflight and every live harness command.

For a sequential, resumable multi-case campaign, use the immutable external
manifest and status commands described in [OIN lab agent sweep
runbook](oin-lab-agent-sweep.md). They never run cases in parallel or select
more than one case for an `active-trace` transaction. The status output blocks
the next command whenever application cleanup, user cleanup, or sanitized
review evidence is unverified. A separate `sweep-audit` performs a final
read-only lookup of every exact campaign app label and ephemeral login.

## Catalog and schema inventory

Catalog inventory is read-only and writes only to the external state root. By
default it retains SAML 2.0 entries; `--include-non-saml` is useful when a report
brand must be classified instead of assumed to be missing:

```bash
.venv/bin/python -m tools.oin_lab catalog \
  --tenant-url https://lab.example.okta.com \
  --snapshot-id 20260814

.venv/bin/python -m tools.oin_lab catalog \
  --tenant-url https://lab.example.okta.com \
  --snapshot-id 20260814-all \
  --include-non-saml
```

The unversioned catalog schema expansion exposes installation-field names,
required flags, enum choices, and descriptions, but not the publisher's hidden
default ACS/entity templates. Schema capture writes a private checkpoint after
every successful application GET. With no target option, this command captures
the schemas for all popularity-derived SAML candidates in the checked-in matrix:

```bash
.venv/bin/python -m tools.oin_lab schemas \
  --tenant-url https://lab.example.okta.com \
  --snapshot-id 20260814-popular
```

Repeat `--app-key` to restrict a schema run. Schema captures can include the
tenant origin in self/schema links and therefore remain external even though
they contain catalog metadata rather than application instances.

To sweep every SAML integration in a dated catalog snapshot, pass that snapshot
as the target source. This remains a sequence of read-only catalog GETs and does
not install or activate applications:

```bash
.venv/bin/python -m tools.oin_lab schemas \
  --tenant-url https://lab.example.okta.com \
  --snapshot-id 20260814-saml-all \
  --catalog-snapshot ~/.local/state/openhound-okta/oin-lab/<tenant-key>/catalog/20260814/applications.json
```

If a transport failure, exhausted `429`/server-error retry, or operator
interruption stops the sweep, rerun the identical command with `--resume`.
Resume requires the same tenant, snapshot ID, target keys, and byte-exact catalog
snapshot; it validates existing checkpoint hashes and recovers a checkpoint that
was written immediately before a state-write interruption. A pre-existing run is
never resumed implicitly.

Read-only schema GETs use bounded exponential retry and honor Okta
`Retry-After`/`X-Rate-Limit-Reset` headers, capped at 60 seconds. A per-app `404`
is recorded as missing and the sweep continues; other non-retryable errors stop
the sweep without discarding completed checkpoints. `--max-attempts` defaults to
four and is bounded from one to ten.

After every target is either captured or recorded missing, the harness writes a
deterministically ordered `applications.json` and its `schema-analysis.json` in
the same external snapshot directory. Raw per-app checkpoints, capture state,
materialized snapshot, and analysis are all mode `0600`.

Analyze an existing schema capture entirely offline. The output defaults to
`schema-analysis.json` beside the input, or `--output` can select another path
outside the repository workspace:

```bash
.venv/bin/python -m tools.oin_lab analyze-schemas \
  --input ~/.local/state/openhound-okta/oin-lab/<tenant-key>/catalog-schemas/20260814-popular/applications.json
```

The analyzer inventories non-sensitive properties from every schema definition,
including `general`, `sso`, `hidden`, and any additional sections. It normalizes
required flags, enums, defaults, types, formats, descriptions, mutability, and
scope into stable app/section/attribute records. Credential-like attributes are
omitted and counted. The command does not require an Okta token, load the probe
matrix, create applications, or make network requests.

Route classifications are conservative research queues, not resolver evidence:

- `explicit_route_input` means the field itself asks for an ACS, entity ID,
  audience, SP URL, destination, or equivalent route component.
- `route_origin_input` marks a base/site/host/instance URL that may participate
  in a route template.
- `route_discriminator` marks account, tenant, domain, region, environment, or
  similar inputs that may select a route variant.
- `route_template_hint` means a non-route field description connects that field
  to an ACS/entity example.
- `catalog_default_hint` is limited to explicit route fields whose schema
  description or default states a default value.

SCIM- and SWA-specific fields are not promoted as SAML route signals. Every app
classification retains `authoritative_route: false` and
`requires_human_review: true`. Keep normalized analyses external too: catalog
descriptions can contain vendor URLs and must be reviewed before any evidence is
promoted into the public route registry.

### 2026-08-14 live checkpoint

An authorized Preview tenant returned 8,120 total catalog entries and 2,108
entries advertising `SAML_2_0`. This is a dated tenant/API observation, not a
universal OIN count; public OIN search counts and tenant-visible catalog counts
can differ. The report dataset contains 97 entries across five cohorts, 67
distinct report names, and 70 distinct mapped SAML catalog keys. Seven mapping
rows are non-SAML in the current catalog and three report products have no
current display-name match.

Schema expansion succeeded for all 70 SAML candidates. Forty-six schemas declare
at least one required installation field; 24 declare none. All 24 zero-required
targets were installed as inactive temporary apps and captured. A separate
ten-case run covered the existing documented GlobalProtect, Salesforce, Slack,
Workday, and Zoom variants. In every case, normal inactive application GETs
returned supplied/default `settings.app` fields and null sign-on route overrides,
not the catalog's hidden default ACS/entity values. SAML metadata was unavailable
for inactive apps. No app was activated, assigned, or provisioned, and every
created app was deleted with an exact-ID/label/key/status check and a confirming
404 readback.

Offline analysis of that 70-app snapshot inventoried 179 non-sensitive
attributes, omitted five credential-like attributes, and reported no malformed
schema diagnostics. The overlapping app-level signals were 23 explicit route
inputs, 13 route-origin inputs, 27 route discriminators, five route-template
hints, and one catalog-default hint. The resulting primary research queue is one
catalog-default review, 11 required and 11 optional explicit-route reviews, 30
route-template candidates, and 17 targets that still need targeted research.
These counts describe this dated snapshot and analyzer rules; they are not OIN
coverage or verified ACS counts.

The resumable full-catalog sweep then captured schemas for all 2,108 SAML keys
from the same dated catalog snapshot. It completed without a missing target or
schema diagnostic, inventoried 2,316 non-sensitive attributes, and omitted 17
credential-like attributes. The overlapping app-level signals were 407 explicit
route inputs, 175 route-origin inputs, 771 route discriminators, 104
route-template hints, and four catalog-default candidates. The primary queue is
four catalog-default reviews, 287 required and 116 optional explicit-route
reviews, 855 route-template candidates, and 846 targets requiring more focused
research. These are structural triage results, not verified route support.

The result narrows the next phase: use schema fields to build reviewed
account/region variant matrices and public setup documentation to prove route
templates. Where the schema requires the ACS, entity, or audience itself, mark
the integration explicit-only rather than creating a fabricated route. Do not
activate catalog apps merely to expose metadata without a separately reviewed
authorization and safety design.

## Cleanup

First preview cleanup. This performs live read-only identity and status checks:

```bash
.venv/bin/python -m tools.oin_lab cleanup \
  --tenant-url https://lab.example.okta.com \
  --run-id 20260813a
```

After reviewing the state, delete only the recorded inactive apps:

```bash
.venv/bin/python -m tools.oin_lab cleanup \
  --tenant-url https://lab.example.okta.com \
  --confirm-tenant-host lab.example.okta.com \
  --run-id 20260813a \
  --confirm-run-id 20260813a \
  --apply
```

Keep the local state until every record has `deleted_at` or an operator has
resolved any explicit `absent_at`/safety failure.

## Promoting evidence into the collector

A live capture is discovery evidence, not an automatic resolver definition.
Before adding a bundled route profile:

1. Compare multiple relevant variants where the catalog exposes environment,
   region, account, product, or multi-IdP options.
2. Confirm which returned fields are materialized from the supplied instance
   values and which are static catalog defaults.
3. Cross-check the route with current Okta or downstream-vendor documentation.
4. Add a public-safe source-shaped fixture with placeholder domains and IDs.
5. Add negative cases for missing, malformed, conflicting, and unsupported
   variants; explicit `settings.signOn` routes retain precedence.
6. Record the evidence URL, reviewed date, required fields, exact route template,
   and variants in `docs/saml-oin-route-evidence.md`.

Do not commit raw captures, tenant identifiers, real downstream routes,
credentials, or the external run-state directory.
