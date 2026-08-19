# Okta OIN SAML route evidence

This document tracks the bounded, evidence-backed expansion of Okta Integration
Network (OIN) SAML route normalization for `os-a186`. It intentionally contains
only aggregate application-family counts and public integration identifiers. It
does not contain customer labels, tenant names, application IDs, routes, or raw
payloads.

## Evidence boundary

The public-collector baseline is a local operator-supplied export filtered to 60
`SAML_FederationProvider` rows across 44 application families with no associated
`SAML_AssertionConsumerService`. Two generated custom-integration families, one
row each, are excluded from the public OIN catalog scope and reserved as
potential future out-of-tree integrations. Of the in-scope rows, 59 report
missing authoritative ACS and SP entity evidence. The remaining `okta_org2org`
row reports that both of its documented explicit instance fields are missing.

The export contains normalized provider properties, not raw `settings.app` or
`settings.signOn` objects. It can establish family frequency, but it cannot
prove that the instance variables required by a new resolver are present. A
family resolver therefore changes potential coverage only until it is replayed
against source-shaped application data.

Generated custom integrations are not candidates for bundled family resolvers.
The public collector can still normalize complete explicit deployed SAML fields,
but it does not ship app-specific route knowledge for those integrations.

## Discovery spike

Reviewed 2026-08-13:

- [Okta's current catalog application model](https://developer.okta.com/docs/api/openapi/okta-management/management/rolebtargetclient)
  exposes catalog identity, protocol, status, and feature metadata. It does not
  expose default ACS or entity templates.
- The legacy, unversioned
  [Catalog API notes](https://gist.github.com/benjaminwesson-okta/8b83cbcb31058c289260)
  describe `/api/v1/catalog/apps/{name}?expand=schema`. Their Salesforce example
  returns installation schema fields such as `instanceType`, `loginUrl`, and
  `customDomain`, but no default SAML route templates. Current compatibility and
  per-family output still require an authorized tenant check.
- The current
  [OIN Wizard submission guide](https://developer.okta.com/docs/guides/submit-oin-app/saml2/main/)
  confirms that publisher submissions contain a default ACS URL, optional
  indexed ACS URLs, an entity ID, and organization-variable expressions. The
  documented workflow is scoped to integrations owned by the publisher; no
  public read API for arbitrary published definitions was found in this spike.
- Public Okta and downstream-vendor setup material can support a deterministic
  family profile only when the deployed application payload contains every
  variable needed to materialize the exact route. App family or label alone is
  never route evidence.
- Undocumented Admin Console endpoints and browser capture were not exercised in
  this initial slice. Any later investigation must use an authorized disposable
  tenant, begin read-only, and keep credentials and captures outside the
  repository.

Authorized Preview-tenant research on 2026-08-14 verified the current legacy
catalog behavior without using an Admin Console capture. A complete read-only
inventory returned 8,120 tenant-visible catalog entries, including 2,108 that
advertise `SAML_2_0`. `GET /api/v1/catalog/apps/{name}?expand=schema` succeeded
for all 70 popularity-derived SAML candidates and exposed required installation
fields and enum choices, but no default ACS/entity templates. These are dated
tenant/API observations rather than universal OIN counts.

Thirty-three inactive temporary apps were then created and captured across the
documented baseline and zero-required-field popularity cohorts. Normal
application payloads retained supplied/default `settings.app` fields, while
all route override fields in `settings.signOn` remained null. Metadata requests
for inactive apps returned unavailable and the apps were never activated.
Every created app was deleted and verified absent; an initial failed create was
also verified to have no exact-label app. The live spike therefore disproves the
working assumption that merely installing an inactive catalog app exposes the
publisher's default route through the ordinary application or metadata APIs.

The public popularity expansion is reproducible in the lab SQL matrix: 97
entries across the official 2024 top-50 chart, the official 2025 top-15
infographic and public growth callouts, and the public 2026 top-15 and
fastest-growing-ten press assets. The 67 distinct report names map to 70 current
SAML catalog keys, seven non-SAML mapping rows, and three currently absent
display-name matches. Brand names with multiple product integrations remain
one-to-many instead of being collapsed to a guessed catalog key.

An isolated, guarded lab harness is now available in `tools/oin_lab`. Its SQL
matrix is reproducible experiment input owned by `openhound-okta`; it is not
persistent simulated-environment state and is never consumed by environment
provisioning or deployment. The harness creates inactive temporary catalog apps,
records native IDs externally, captures raw and sanitized review evidence, and
deletes only exact recorded inactive matches. See
[Ephemeral OIN lab research](development/oin-lab-research.md).

The bounded result is therefore: there is no reviewed universal public route
definition source. Coverage must be added through explicit deployed fields or
small, allowlisted family resolvers with public route evidence and strict input
validation.

The subsequent resumable sweep captured all 2,108 SAML schemas in the dated
catalog snapshot. It produced 2,316 non-sensitive attributes, no missing schema,
and no malformed-schema diagnostics. Structural triage identified 407 apps with
explicit route inputs, 855 route-template candidates, 846 targets without a
route-oriented schema signal, and four apps whose schema descriptions mention a
default route. These queues overlap at the signal level and are not verified
route coverage.

### Miro default promotion

The `realtime_board` catalog schema identifies optional `customAcsUrl` and
`customEntityId` fields and states the standard defaults as
`https://miro.com/sso/saml` and `https://miro.com/`. An inactive default catalog
instance returned both fields as null. Current [Miro SSO
documentation](https://help.miro.com/hc/en-us/articles/360017571414-Single-sign-on-SSO)
publishes the same standard ACS and entity values and documents distinct
data-residency routes. Miro's current [Okta setup
guide](https://help.miro.com/hc/en-us/articles/360023901054-How-to-configure-OKTA-SSO)
confirms that the catalog integration pre-fills the expected sign-on values and
permits customized values.

The bundled Miro resolver therefore emits the documented static route only when
both custom fields are present and explicitly null. Omitted fields do not prove
that the catalog default was selected. In every other case, both fields must be
complete, clean HTTPS URLs on `miro.com` or a subdomain of `miro.com`; otherwise
the resolver fails closed. Complete custom values are preserved exactly rather
than converted through a guessed data-residency or multi-IdP template. Complete
explicit `settings.signOn` evidence continues to take precedence.

### Asana default promotion

An authorized Preview1 active trace on 2026-08-15 created the standard `asana`
catalog integration with no application settings, assigned exactly one
ephemeral non-administrative user, and intercepted a SAML response before it
was delivered to Asana. The assertion used ACS and recipient
`https://app.asana.com/-/saml/consume` with audience
`https://app.asana.com`. The catalog schema exposed no configurable
attributes, and the inactive instance had no enabled features, provisioning,
assignment inheritance, or sign-on route overrides. The harness deleted and
verified deletion of both the exact recorded app and user after the trace.

Current [Asana authentication
documentation](https://help.asana.com/s/article/authentication-and-access-management-options-for-paid-plans?language=en_US)
publishes the same ACS and an SP metadata entity ID of
`https://app.asana.com/`. The actual Okta OIN assertion audience omitted that
trailing slash, so the resolver preserves the observed OIN value exactly rather
than substituting the generic metadata value. Okta's current [Asana setup
guide](https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-for-Asana.html)
corroborates the supported Okta-to-Asana SAML flow.

This evidence proves the route emitted by the standard Okta OIN integration;
it does not prove successful Asana sign-in, downstream account configuration,
or every historical catalog version. Complete explicit `settings.signOn`
evidence remains authoritative if a deployed instance differs.

### Source-shaped five-family validation

On 2026-08-18, five SQL-backed native OIN applications were provisioned in an
authorized Preview tenant and collected from the exact working tree under
review. The set covered `asana`, `panw_globalprotect`, `slack`, `zoomus`, and
`realtime_board`, with one active non-administrative user assignment per app.
The collected source objects preserved the expected selector fields, including
explicitly null Miro custom-route fields and Okta-emitted null Zoom route
fields.

Normalization produced five federation providers, five assertion consumer
services, and five `SAML_IssuesAssertionsTo` relationships with no route or
issuer diagnostics. A filtered additive upload to a disposable BloodHound CE
appliance ingested all five files without errors or warnings; post-analysis
queries returned the same five complete application-provider-ACS tuples. No
assertion was delivered to a downstream service, so this validates Okta source
shape through graph ingestion rather than downstream product sign-in.

Compared with the preceding Preview-tenant control run, wall time changed by
approximately +1.0 percent for collection, -0.9 percent for preprocessing, and
+3.7 percent for conversion while processing five additional applications;
peak memory was effectively unchanged. The result does not indicate a material
OIN resolver performance regression.

## Maintenance architecture

OIN route knowledge is bundled with `openhound-okta` under
`src/openhound_okta/oin_routes`. It is deliberately not loaded as executable
runtime plugins and is never fetched during collection. This keeps normalized
output deterministic and ties every profile change to collector review,
fixtures, and release versioning.

The package has two extension paths behind one typed, multi-route contract:

- Declarative profiles describe stable application keys, validated instance
  variables, exact ACS/entity templates, provenance, and reviewed evidence.
  These are preferred for ordinary deterministic catalog integrations.
- Small code resolvers handle exceptional selection or conditional behavior
  that cannot be represented safely as a template. They return the same route
  and diagnostic structure as declarative profiles.

The registry rejects duplicate application keys at import time. Unknown keys,
invalid inputs, and incomplete variables return no routes. Catalog research and
generation tools may eventually prepare proposed profile updates, but reviewed
profiles remain package data rather than a live network dependency. A separate
plugin or package boundary should only be considered if out-of-tree private
integrations or an independent release cadence becomes a demonstrated need.

OIN route-related application settings use a small graph-expression contract.
Equivalent Okta spellings are normalized to canonical names (for example,
`subdomain` and `subDomain` both become `sub_domain`), direct ACS/entity/audience
fields are separately allowlisted from resolver selectors, and every resolver
declares the raw `settings.app` fields it reads. A contract test requires each
declared dependency to be either emitted on `Okta_Application` or accompanied
by an explicit collection-time-only rationale.

`Okta_Application.saml_route_setting_fields` records only the canonical names
of safe allowlisted route fields present in the source object. It deliberately
includes a field name when the source value is null, while the value property
itself remains absent. This makes default-versus-unknown review possible for
cases such as Miro without exposing arbitrary setting names or credential-like
values.

## Family matrix

`Explicit-only` means the integration remains supported through complete
`settings.signOn` evidence, but no family default is synthesized. `Deferred`
means the family needs a separate current source review. A deferred or invalid
instance remains fail closed.

| Application family key | Rows | Source category | Authoritative source or required instance evidence | Exact route template when proven | Current verdict |
| --- | ---: | --- | --- | --- | --- |
| `panw_globalprotect` | 10 | Public Okta guide plus downstream route documentation and live catalog validation | `settings.app.baseURL`; [Okta setup guide](https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-for-Palo-Alto-Networks-GlobalProtect.html); [Palo Alto route documentation](https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-advanced-deployments/mobile-user-globalprotect-advanced-deployments/configure-multiple-portals-in-prisma-access) | ACS `<baseURL>/SAML20/SP/ACS`; entity `<baseURL>/SAML20/SP` | Implemented conditionally; malformed, non-HTTPS, or non-origin `baseURL` fails closed. A 2026-08-14 inactive lab replay confirmed the case-sensitive field and retained input, but the ordinary app payload did not materialize routes. Source-shaped customer replay remains unavailable. |
| `salesforce` | 5 | Catalog schema plus downstream-generated configuration | Legacy schema exposes `instanceType`, `loginUrl`, and `customDomain`, but not the effective Salesforce SSO setting. Require explicit deployed route or downstream metadata. | Not proven for all My Domain, sandbox, and login-domain variants. | Deferred; explicit-only. |
| `slack` | 2 | Public Okta API schema plus Okta and Slack route documentation | `settings.app.domain`; current Okta schema requires `domain`, Okta documents including `.enterprise` for Enterprise Grid, and Slack documents the workspace/organization ACS plus default entity. | ACS `https://<domain>.slack.com/sso/saml`; entity `https://slack.com`. | Implemented conditionally for a validated workspace label or `<label>.enterprise`; explicit `settings.signOn` remains authoritative for a customized issuer. Workspace and Enterprise Grid inactive lab variants retained the supplied domain; no route fields were materialized. |
| `scim2testapp` | 2 | Test/private integration | Require explicit ACS, audience, and effective SAML protocol fields from the deployed test service. | Instance-defined. | Fail closed unless explicit route evidence is complete. |
| `workday` | 2 | Catalog integration with tenant/environment-specific downstream configuration | `siteURL` alone is insufficient; require the effective Workday ACS/entity or downstream metadata. | Not yet proven for tenant and data-center variants. | Deferred; explicit-only. Inactive lab replay retained a reserved `siteURL` but exposed no materialized route. |
| `adobecreativecloud` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `alertmediacom` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `amazon_aws_sso` | 1 | Catalog integration with ambiguous AWS target mode | Require the actual AWS SAML target and deployed ACS/entity evidence; do not alias this key to another AWS family. | Not proven for this catalog key. | Deferred; explicit-only. |
| `asana` | 1 | Active Okta OIN trace plus current Asana and Okta documentation | The standard catalog integration has no configurable application attributes; the captured assertion supplies the exact OIN audience. Complete explicit `settings.signOn` evidence remains authoritative. | ACS `https://app.asana.com/-/saml/consume`; entity `https://app.asana.com`. | Implemented as an allowlisted static default. The live assertion was intercepted before delivery, so downstream Asana sign-in was not tested. |
| `atlassian` | 1 | Catalog integration with site/organization-specific downstream configuration | Require exact Atlassian organization/site evidence and deployed route. | Not proven. | Deferred; explicit-only. |
| `boxnet` | 1 | Catalog integration | Legacy catalog metadata identifies SAML support but exposes no route template. Require deployed route or downstream metadata. | Not proven. | Deferred; explicit-only. |
| `ciscocommonidentity` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `ciscomeraki` | 1 | Catalog integration | Require exact Meraki organization/SP configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `citrixnetscalergateway_saml` | 1 | Catalog integration with gateway-specific downstream configuration | Require the exact gateway FQDN and deployed Citrix SAML route evidence. | Not proven. | Deferred; explicit-only. |
| `cloudconsole` | 1 | Ambiguous catalog family | App key alone does not identify a route contract. Require explicit deployed route evidence. | Not proven. | Deferred; explicit-only. |
| `datadog` | 1 | Catalog integration | Require exact Datadog site/organization configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `dialpad` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `docusign` | 1 | Catalog integration with account/environment variants | Require exact account/environment route and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `getpostman` | 1 | Catalog integration | Require exact Postman organization/team SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `island` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `island_managementconsole` | 1 | Catalog integration distinct from `island` | Do not alias the two keys; require exact management-console configuration. | Not proven. | Deferred; explicit-only. |
| `logicmonitor` | 1 | Catalog integration | Require exact account/domain SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `logmein` | 1 | Catalog integration with product/account variants | Require exact product and account route evidence. | Not proven. | Deferred; explicit-only. |
| `mimecastadmin` | 1 | Catalog integration distinct from Mimecast Personal Portal | Require exact region/product configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `mimecastppv3` | 1 | Catalog integration distinct from Mimecast Admin | Require exact region/product configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `motus` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `navan` | 1 | Catalog integration | Require exact organization configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `novatus` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `odesk` | 1 | Legacy catalog integration | Current target product and route stability require verification. | Not proven. | Deferred; explicit-only. |
| `okta_org2org` | 1 | Explicit OIN instance fields | `settings.app.acsUrl` and `settings.app.audRestriction` are authoritative. | Exact values are emitted without construction. | Resolver already supported; observed row lacks both fields and correctly fails closed. |
| `oraclecloudinfrastructureiam` | 1 | Catalog integration with tenancy-specific downstream configuration | Require tenancy/region-specific authoritative route evidence and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `pagerduty` | 1 | Catalog integration | Require exact account/subdomain configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `paloaltonetworkssaml` | 1 | Separate Palo Alto catalog family | Do not alias to `panw_globalprotect`; require family-specific settings and route verification. | Not proven for this key. | Deferred; explicit-only. |
| `readcube` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `realtime_board` | 0 | Catalog schema plus current Miro documentation | Explicitly present, null `customAcsUrl` and `customEntityId` fields select the documented standard route; omitted fields do not. Complete custom values are authoritative for documented data-residency and multi-IdP variants. | Standard ACS `https://miro.com/sso/saml`; entity `https://miro.com/`. Custom values are preserved exactly. | Implemented conditionally. Missing, partial, malformed, non-HTTPS, or non-Miro custom values fail closed. This family was not present in the supplied customer baseline and does not change its potential recovered-row count. |
| `servicenow_ud` | 1 | Catalog integration with instance-specific downstream configuration | Require exact ServiceNow instance and SAML configuration; instance URL alone is not yet accepted as the route tuple. | Not proven. | Deferred; explicit-only. |
| `sentry` | 1 | Catalog integration | Require exact organization SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `sharefile` | 1 | Catalog integration with account/region variants | Require exact account control plane and route evidence. | Not proven. | Deferred; explicit-only. |
| `showpad` | 1 | Catalog integration | Require exact organization/subdomain configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `simplelegal` | 1 | Catalog integration | No route-authoritative collected field or public template verified in this spike. | Not proven. | Deferred; explicit-only. |
| `tableauonline` | 1 | Catalog integration with site/pod-specific downstream configuration | Require exact site/pod SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `vanta` | 1 | Catalog integration | Require exact organization SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `workiva` | 1 | Catalog integration with region/account variants | Require exact region/account SAML configuration and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `xmatters` | 1 | Catalog integration with instance/region variants | Require exact instance/region route evidence and reviewed collected variables. | Not proven. | Deferred; explicit-only. |
| `zoomus` | 1 | Public Okta API schema plus Zoom's Okta integration documentation | `settings.app.subDomain` for the single-vanity variant. Zoom documents separate downstream-generated ACS/entity values when multiple vanity URLs or IdPs are enabled. | Single vanity: ACS `https://<subDomain>.zoom.us/saml/SSO`; entity `https://<subDomain>.zoom.us`. | Implemented conditionally only when `subDomain` is one validated host label. Multi-IdP/multi-vanity remains explicit-only. Inactive lab replay retained `subDomain`; `acs_url` and `audience_uri` remained null. |

## Coverage checkpoint

| Measure | Baseline | After this slice |
| --- | ---: | ---: |
| In-scope observed rows | 60 | 60 |
| In-scope observed families | 44 | 44 |
| Rows with routes proven by the supplied normalized export | 0 | 0 |
| Rows eligible for the new `panw_globalprotect` resolver if raw `baseURL` is valid | 0 | 10 |
| Rows eligible for new Slack and single-vanity Zoom resolvers if required raw fields and variants are valid | 0 | 3 |
| Rows eligible for the Asana default resolver | 0 | 1 |
| Families with a newly implemented resolver | 0 | 5 |

The combined 14-row figure is potential coverage, not an assertion about the
customer instances. The Asana default is supported by an active Okta OIN trace;
source-shaped replay is still required to confirm that the customer row is the
same standard variant. Each variable route also requires its corresponding
`settings.app` field and enough evidence to distinguish supported variants
before it can be counted as recovered. The 80 percent ticket target is
therefore not yet met.

## Resolver contract

OIN resolvers are registered by the stable Okta application key, but the key
only selects a declarative profile or exceptional validation function. A
resolver must still validate every required instance value and emit source-field
provenance. Resolvers can preserve multiple authoritative ACS/entity tuples.
Complete explicit `settings.signOn` routes retain precedence. Conflicting
explicit and derived routes remain diagnostic, and unknown or incomplete
families emit no ACS node.

For `panw_globalprotect`, the initial resolver accepts only a complete HTTPS
origin in `settings.app.baseURL`. It rejects credentials, whitespace,
expressions, non-HTTPS schemes, paths, query strings, fragments, and malformed
hosts or ports. It preserves the supplied authority, including an explicit
port, and appends only the documented GlobalProtect SP paths.
