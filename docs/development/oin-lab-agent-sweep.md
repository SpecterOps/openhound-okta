# OIN lab agent sweep runbook

This runbook is the bounded handoff contract for an agent gathering Okta OIN
SAML route evidence. It assumes the operator has authorized a specific lab
tenant and active temporary integrations. It does not authorize changes to
tenant policy, downstream services, persistent simulated-environment state, the
route registry, or public documentation.

The campaign tooling is deliberately sequential. Every generated command
creates at most one catalog app and one purpose-built Okta-only user, captures
at most one outbound SAML response, and must verify deletion of both objects
before another case may begin.

"Exactly one" is a concurrency and cleanup boundary, not a stop-after-one-case
instruction. During an authorized sweep, repeat `sweep-status` -> its one
`next_command` -> `sweep-status` -> worksheet until all cases are attempted or
a mandatory stop condition occurs.

## Definition of done

A capture campaign is operationally complete only when:

- `sweep-status` reports `all_cases_attempted: true` and
  `safe_to_continue: true`;
- `cleanup_unverified` and `review_invalid` are both zero;
- `campaign_failure` is zero;
- `sweep-audit` reports zero application and user residue;
- every `captured_clean` review has a recorded human or agent evidence verdict;
- every `attempted_clean_no_capture` case has a failure category and is not
  treated as a route; and
- raw state remains external and nothing tenant-specific is committed.

`all_cases_captured` is not expected. Some integrations legitimately require a
configured downstream account, SP-initiated request, region, realm, or other
authoritative input unavailable to the lab.

## Operator-provided inputs

The delegating operator must provide these values without placing a token in the
prompt or command history:

- exact authorized Okta tenant URL and hostname;
- an external owner-only state root;
- a short unique sweep ID using lowercase letters, digits, and hyphens;
- the set of cases, or authorization to attempt every non-blocked matrix case;
- confirmation that `OKTA_API_TOKEN` is already present in the process
  environment; and
- confirmation that the work is evidence gathering plus the bounded harness
  maintenance described below; resolver or product implementation remains out
  of scope unless separately requested.

The agent must never open, print, copy, summarize, or commit the token. A custom
environment variable may be selected with `--token-env` when the operator has
already populated it.

## One-time preflight

Work from the `openhound-okta` repository. Install the optional dependency and
Chromium if the operator has not already done so:

```bash
uv sync --group dev --group oin-lab
uv run playwright install chromium
```

When `PLAYWRIGHT_BROWSERS_PATH` is used, export the same external path for both
installation and every later trace. If the agent runtime restricts outbound
network access, obtain authorized access to the named Okta tenant for both the
preflight and every live harness command. Then run the preflight:

```bash
.venv/bin/python -m tools.oin_lab active-preflight \
  --tenant-url https://lab.example.okta.com \
  --state-root /external/oin-lab-state
```

This checks token presence and format, rejects a repository-local state path,
performs one read-only Management API application lookup, imports Playwright,
and launches and closes Chromium. It never prints the token and creates no
tenant object. Require both `management_api_read_verified: true` and
`browser_launch_verified: true`; do not start or resume a sweep otherwise.

## Create the immutable campaign

Keep the sweep ID short because it is incorporated into every Okta label and
ephemeral login. To plan every `ready` and `discovery` case while excluding
`blocked` cases:

```bash
.venv/bin/python -m tools.oin_lab sweep-plan \
  --tenant-url https://lab.example.okta.com \
  --state-root /external/oin-lab-state \
  --sweep-id 20260815p1 \
  --include-discovery
```

Without `--include-discovery`, only `ready` cases are selected. To run a bounded
subset, repeat `--case` and add `--include-discovery` if any selected case is in
that state:

```bash
.venv/bin/python -m tools.oin_lab sweep-plan \
  --tenant-url https://lab.example.okta.com \
  --state-root /external/oin-lab-state \
  --sweep-id 20260815p1 \
  --case slack-workspace \
  --case asana-default \
  --include-discovery
```

Planning makes no network request. It writes an owner-only manifest outside the
repository. The manifest pins the tenant, matrix digest, exact ordered cases,
and a unique run ID for every case. If the matrix or selection changes, use a
new sweep ID; never modify the manifest.

## Execute exactly one case at a time

Ask for current status before every trace:

```bash
.venv/bin/python -m tools.oin_lab sweep-status \
  --tenant-url https://lab.example.okta.com \
  --state-root /external/oin-lab-state \
  --sweep-id 20260815p1
```

The output is machine-readable JSON. Interpret it as follows:

| Field or status | Required action |
| --- | --- |
| `operator_action: run_exactly_one_next_command` | Execute the `next_command` argument array exactly once, without adding cases or changing the run ID. |
| `captured_clean` | The sanitized SAML response exists and app/user cleanup is recorded. Review the evidence before drawing a conclusion. |
| `attempted_clean_no_capture` | No usable response was captured, but absence of the temporary objects is verified. Record the failure category; unless it indicates a campaign-wide problem, continue with the next emitted case. |
| `case_running` | The original `active-trace` command has not completed. Wait on that exact tool/session until it exits, then rerun `sweep-status`; do not write a worksheet or run another command. |
| `campaign_failure` | Cleanup is verified, but transport, authorization, tenant policy, identity isolation, or another campaign-scoped failure requires operator resolution. Stop even though no residue remains. |
| `cleanup_unverified` | Stop immediately. Do not run the next case. Escalate to the operator for exact-object review. |
| `review_invalid` | Stop immediately. Preserve external state and investigate the malformed or missing sanitized evidence. |
| `campaign_attempts_complete_human_review_required` | Do not run more cases. Complete evidence review and the final residue audit. |

`safe_to_continue` means no confirmed safety failure is present. A
`case_running` report may therefore be safe while still authorizing no next
case; only a non-null emitted `next_command` authorizes another trace. For a
completed case, safe status also requires locally verified cleanup and valid
review-file structure. It does not mean that the previous failure was
understood or that a route is authoritative.

Default output is deliberately compact: aggregate counts, the last attempted
case, any blocking cases, and the single next command. Use `--details` only at a
review checkpoint or final handoff when the complete per-case result list is
needed; do not spend context repeatedly loading all pending rows.

Run the single `next_command` exactly as emitted. Never put it in `xargs`, a
parallel runner, a background job, or an unattended shell loop. An agent tool
yielding a session/cell ID, a continuation handle, or a `still running` result
does not mean the command returned. Wait on that same handle until the process
has an exit code. Only then run `sweep-status`. If status reports
`operator_action: wait_for_current_case`, return to the original command session
or poll status until it finishes; do not classify cleanup or write a worksheet
from that intermediate state.

If post-command status is safe, write the worksheet and continue in the same
task. Do not return to the operator merely because one case is
`captured_clean` or `attempted_clean_no_capture`. After three consecutive
clean-no-capture cases with the same operational symptom, pause the case loop
and investigate the shared cause. Continue when schema, tenant readback, or
focused harness tests support case-specific outcomes or a bounded harness fix;
stop only when the evidence supports a campaign-wide condition.

`active-trace` records a stable `failure_category` and `failure_scope` without
persisting the raw error text. A case-scoped failure with verified cleanup is a
completed attempt: the command returns its state normally and the agent should
continue. Per-app HTTP 400, 403, and 404 responses are case-scoped because OIN
integrations commonly reject missing catalog settings with those statuses; a
read-only preflight has already established tenant access. HTTP 401, rate
limits, transport errors, safety invariants, and unknown failures remain
campaign-scoped. `sweep-status` reports those as `campaign_failure`, emits no
next command, and requires operator review. Never infer cleanup state from the
`active-trace` process exit alone; the exact post-command `sweep-status` result
is authoritative.

Expected downstream navigation failures such as DNS resolution, connection
refusal, connection timeout, unreachable address, invalid URL, or an aborted
non-SAML navigation are case-scoped `downstream_navigation_failed` outcomes
after verified cleanup. They usually mean a synthetic account/site value does
not correspond to a live downstream service. Playwright can report the original
Okta app-link URL when a redirect target fails, so the URL displayed in the
exception does not identify which host failed. Playwright launch failures,
browser/context crashes, and unrecognized browser exceptions remain
campaign-scoped because they may invalidate every later trace.

The agent may investigate case-scoped catalog failures without operator approval:
capture that app's schema with the read-only `schemas` command under the
external state root, inspect its normalized analysis, consult first-party
documentation, and record `explicit_only`, `parameterized_candidate`,
`variant_matrix_incomplete`, or `downstream_blocked` as supported. It may create
or update external worksheets and continue. It must not reuse the consumed run
ID, invent a route, edit the immutable manifest, weaken cleanup, or supply real
customer/downstream values.

`active-trace` performs that schema check automatically before creating an app.
Missing required ACS, entity ID, audience, destination, recipient, or equivalent
administrator-supplied route fields produce the case-scoped category
`required_explicit_route_input`. No app or user is created, verified absence is
recorded, and the worksheet verdict is `explicit_only`. Missing required
non-route fields are populated with deterministic lab-only values: reserved
`.invalid` URLs or email addresses, a run-scoped slug, the first catalog enum,
or a primitive boolean/number. State records field names and generation
strategies, not generated values. Unsupported required field types remain a
clean case-scoped outcome.

This campaign is also authorized for bounded harness maintenance. When cleanup
is verified and evidence shows a defect in `tools/oin_lab` rather than a tenant
hazard, the agent may inspect and minimally update the harness, its focused tests,
and these two OIN lab runbooks; run the focused tests and static checks; then
continue with the next unconsumed command emitted by `sweep-status`. This does
not authorize changes to the immutable sweep manifest, route resolvers,
normalization fixtures, public route claims, tenant policy, or downstream
services, and it does not authorize commit or push. A change that weakens exact
app/user identity or cleanup verification still requires operator review.

The harness waits for assignment propagation and accepts multiple launch links
only when every link belongs to the exact temporary app and remains on the
confirmed Okta tenant. An ordinary broad case traces the first Okta-ordered
link and records the available count and labels. A reviewed recovery case may
pin an observed dynamic label suffix in the SQL matrix; the harness then
requires exactly that link and never falls back to another product link. When
an unpinned case has `available_count` greater than one, record
`variant_matrix_incomplete`; the remaining links belong in a later explicit
variant sweep and are not a reason to halt the broad campaign.

Some SSO-only catalog apps require an app-specific profile at assignment time.
Recovery cases may provide a synthetic, non-secret assignment profile in the
matrix. The immutable manifest records that input, the active state records
only its field names, and cleanup retains the same one-user boundary. Do not
add real downstream accounts, roles, identifiers, or credentials.

Do not use the first live case as a connectivity test. In an agent sandbox,
`OktaTransportError` commonly means the command lacked approved outbound
network access even when the tenant URL and token are correct. Return to
`active-preflight` with the required network authorization; never retry the
same run ID after a failed create request, because the POST outcome may be
ambiguous.

If a command fails because of authentication, browser installation, tenant
policy, rate limiting, or another campaign-wide condition, stop and correct the
environment with the operator. Do not consume the remaining cases as identical
failures. A per-integration lack of an outbound SAML response may be recorded as
`attempted_clean_no_capture` only after cleanup is verified.

## Review each successful capture

The `evidence` object for `captured_clean` contains only the sanitized review
path, request URL, method, message type, Destination/Recipient values, and
Audience values. The assertion, NameID, attributes, credentials, TOTP seed, and
RelayState value are not retained.

For each captured case, review both the sanitized inactive application snapshot
and sanitized active trace. Record this external worksheet row:

```text
case_id:
app_key:
variant:
run_id:
campaign_status: captured_clean | attempted_clean_no_capture
cleanup_verified: yes | no
acs_or_request_url:
destinations_and_recipients:
audiences:
schema_inputs_used:
first_party_sources:
source_review_date:
verdict: static_candidate | parameterized_candidate | variant_matrix_incomplete | explicit_only | downstream_blocked | no_capture
notes:
```

Use current first-party Okta or downstream-vendor documentation. Record the
direct URL and review date, paraphrase the relevant contract, and distinguish a
generic SP metadata entity from the exact Audience emitted by Okta. Search
results, community answers, copied configuration blogs, and the inactive
Okta-generated IdP metadata are discovery leads, not sufficient authority.

Apply these verdict rules:

- `static_candidate`: the standard catalog integration emits the same complete
  route without account, region, realm, or multi-IdP inputs, and current
  first-party documentation corroborates it.
- `parameterized_candidate`: all route components are reproducible from
  collected `settings.app` fields under a reviewed, validated template.
- `variant_matrix_incomplete`: the schema or documentation exposes choices that
  have not all been captured. Gather the missing cases before promotion.
- `explicit_only`: the schema asks the administrator for the ACS, entity, or
  audience itself, or the downstream service generates the authoritative route.
- `downstream_blocked`: Okta cannot emit a response without a real downstream
  tenant, SP-initiated request, or unsupported challenge.
- `no_capture`: the trace produced no usable SAML response and no stronger
  conclusion is justified.

A capture proves what Okta emitted for that synthetic matrix variant. It does
not prove successful downstream sign-in, customer-instance coverage, route
stability across catalog releases, or resolver correctness.

## Mandatory stop conditions

Stop the campaign and preserve external state when any of these occurs:

- `safe_to_continue` is false, `campaign_failure` is nonzero, or
  `sweep-status` exits with code 3;
- an app or user cannot be proven absent;
- an application is unexpectedly active, has an unapproved feature, or has an
  unexpected assignment;
- more than one object matches an exact probe label;
- the browser requests email, push, WebAuthn, policy changes, or credentials
  other than the ephemeral password and its software TOTP;
- the flow would contact or configure a real downstream account;
- the matrix or immutable manifest no longer matches;
- a raw or review file appears inside the repository; or
- resolving the problem would require changing tenant policy, group
  assignments, provisioning, or another system outside the authorized harness.

Do not delete or modify an unexpected object. Report its case and run ID without
copying native IDs, user logins, tenant-specific URLs, or secrets into public
files.

## Final live residue audit

After all cases have been attempted, run the read-only audit:

```bash
.venv/bin/python -m tools.oin_lab sweep-audit \
  --tenant-url https://lab.example.okta.com \
  --state-root /external/oin-lab-state \
  --sweep-id 20260815p1 \
  --max-attempts 4
```

The audit performs exact-label application lookups and exact-login user lookups
for every manifest entry. It makes no changes and reports only residue counts
and any non-clean per-case rows. Add `--details` only when every clean per-case
boolean is needed. Completion requires `clean: true`, zero application residue,
and zero user residue. Each exact read retries HTTP 429 responses with bounded
exponential delay, honors `Retry-After` and `X-Rate-Limit-Reset`, and caps each
delay at 60 seconds. `--max-attempts` defaults to four and is bounded from one
to ten. An exhausted 429 or exit code 3 means stop and escalate.

## Handoff output

Return a concise campaign summary containing:

- manifest path and matrix digest;
- attempted, captured, clean-no-capture, and blocked counts;
- zero-residue audit result;
- the external worksheet path;
- route candidates grouped into static, parameterized, incomplete-matrix,
  explicit-only, and downstream-blocked categories;
- official source URLs for every candidate;
- any bounded harness/test/runbook changes and their validation result; and
- a statement that no resolver, normalization fixture, ticket, commit, push,
  or downstream sign-in was performed unless separately authorized.

The evidence-gathering agent must not copy raw captures into the repository or
promote a route automatically. Resolver implementation remains a separate
reviewed change with source-shaped fixtures, negative cases, explicit-route
precedence, and fail-closed behavior.

## Delegation prompt

The operator can give a lower-cost agent this bounded instruction after
providing the environment variables and exact tenant/state/sweep values:

```text
Follow docs/development/oin-lab-agent-sweep.md exactly. Perform evidence
gathering and the bounded harness maintenance it authorizes. Ensure the live
commands have authorized outbound access to the operator-named Okta tenant. Run
active-preflight and require both API-read and browser-launch verification,
resume the immutable sweep, and repeat the status -> one emitted next_command
-> status -> worksheet loop until all cases are attempted or a mandatory stop
applies. Do not return after one clean case. Never run cases in parallel or
continue after unverified cleanup, invalid review evidence, a substantiated
`campaign_failure`, or another mandatory stop. Treat the exact post-command
`sweep-status` as authoritative rather than interpreting a trace error as a
cleanup failure. Investigate repeated clean case failures and make minimal,
tested `tools/oin_lab`, focused-test, or OIN-runbook corrections when the
runbook permits; do not weaken identity or cleanup gates. A tool yield with a
session/cell ID is still the same running case: wait for its exit before status
or worksheet work. Treat `wait_for_current_case` as an instruction to wait, not
as a cleanup failure. Keep all captures and notes outside the repository. For
each attempted case, record the required
worksheet fields and use only current first-party sources for route
corroboration. Finish with sweep-status and the read-only sweep-audit. Do not
edit resolvers, normalization fixtures, tickets, the immutable manifest, or git
history; do not commit or push.
```
