# Okta OIN SAML route normalization

This document defines the public, production boundary for deriving SAML
assertion consumer service (ACS) and service-provider entity values from Okta
Integration Network (OIN) applications.

OIN research and live catalog experimentation are maintained separately from
this extension. They are not packaged with `openhound-okta`, loaded during
collection, or required during normalization.

## Evidence boundary

Complete deployed values from `settings.signOn` are authoritative. An OIN
resolver is considered only when explicit route evidence is absent and the
stable Okta application key selects a reviewed profile. The profile must still
validate every required instance value; an application key or label alone is
never sufficient route evidence.

Unknown integrations, incomplete inputs, conflicting inputs, and unsupported
variants fail closed and emit no synthesized ACS. Generated custom integrations
remain supported only through complete explicit deployed route fields.

## Resolver architecture

Production route knowledge is bundled under `src/openhound_okta/oin_routes`.
It is never fetched or loaded as executable plugins at runtime. This keeps graph
output deterministic and ties every route change to collector review, fixtures,
and release versioning.

The registry supports two implementations behind one typed, multi-route
contract:

- declarative profiles for validated variables and exact route templates; and
- small code resolvers for exceptional conditional behavior.

The registry rejects duplicate application keys. Resolvers preserve distinct
ACS/entity tuples when their index, binding, or default metadata differs and
remove only exact duplicate tuples.

## Shipped profiles

| Okta application key | Required source evidence | Normalized route |
| --- | --- | --- |
| `asana` | Standard catalog integration without conflicting explicit route fields | ACS `https://app.asana.com/-/saml/consume`; entity `https://app.asana.com` |
| `okta_org2org` | `settings.app.acsUrl` and `settings.app.audRestriction` | Exact collected ACS and entity values |
| `jamfsoftwareserver` | Validated `settings.app.domain` | ACS `https://<domain>/saml/SSO`; entity `https://<domain>/saml/metadata` |
| `githubenterprisemanageduser` | Validated `settings.app.enterpriseName` | GitHub Enterprise SAML consume and entity routes |
| `githubcloud` | Validated `settings.app.githubOrg` or `settings.app.orgName` | GitHub organization SAML consume and entity routes |
| `panw_globalprotect` | Complete HTTPS origin in `settings.app.baseURL` | ACS `<baseURL>/SAML20/SP/ACS`; entity `<baseURL>/SAML20/SP` |
| `slack` | Validated workspace or Enterprise Grid value in `settings.app.domain` | ACS `https://<domain>.slack.com/sso/saml`; entity `https://slack.com` |
| `zoomus` | One validated vanity label in `settings.app.subDomain` | ACS `https://<subDomain>.zoom.us/saml/SSO`; entity `https://<subDomain>.zoom.us` |
| `realtime_board` | Both Miro custom fields present and null, or both complete validated Miro URLs | Documented standard route or exact custom route |

Each provider records its evidence references and review date in the registry.
Adding another family requires current authoritative route documentation,
source-shaped fixtures, negative cases, and explicit provenance for every route
component.

### Asana default promotion

The standard `asana` catalog integration exposes no application setting needed
to select an account, region, or IdP-specific route. A reviewed OIN assertion
used ACS and recipient `https://app.asana.com/-/saml/consume` with audience
`https://app.asana.com`.

Current [Asana authentication documentation](https://help.asana.com/s/article/authentication-and-access-management-options-for-paid-plans?language=en_US)
publishes the same ACS and an SP metadata entity ID with a trailing slash. The
resolver preserves the exact OIN assertion audience without the trailing slash.
Okta's current [Asana setup guide](https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-for-Asana.html)
corroborates the supported Okta-to-Asana flow. Complete explicit deployed route
fields remain authoritative.

### Miro default promotion

The `realtime_board` catalog schema exposes optional `customAcsUrl` and
`customEntityId` fields. The resolver selects the documented standard route
only when both keys are present and explicitly null. Omitted fields do not prove
that the catalog default was selected.

Current [Miro SSO documentation](https://help.miro.com/hc/en-us/articles/360017571414-Single-sign-on-SSO)
and [Miro's Okta setup guide](https://help.miro.com/hc/en-us/articles/360023901054-How-to-configure-OKTA-SSO)
document standard ACS `https://miro.com/sso/saml` and entity
`https://miro.com/`, along with customized and data-residency variants.
Complete custom values are preserved only when both are clean HTTPS Miro URLs;
partial, malformed, or non-Miro values fail closed.

## Application-setting graph contract

Equivalent Okta spellings are normalized to canonical graph property names.
Direct ACS/entity/audience fields are separately allowlisted from resolver
selectors, and every resolver declares the raw `settings.app` fields it reads.
A contract test requires each dependency to be graph-expressed or explicitly
documented as collection-time-only.

`Okta_Application.saml_route_setting_fields` contains only canonical names of
safe allowlisted route fields present in the source object. A field name remains
present when its source value is null, while the value property is omitted. This
supports default-versus-unknown analysis without exposing arbitrary setting
names or credential-like values.

## Resolver contract

A resolver must:

1. select only by a stable Okta application key;
2. validate every required instance value before constructing a route;
3. preserve exact route values and source-field provenance;
4. retain multiple authoritative routes and their endpoint metadata;
5. defer to complete explicit `settings.signOn` evidence;
6. report conflicts and incomplete evidence diagnostically; and
7. emit no route for unknown, malformed, partial, or unsupported variants.

For example, the GlobalProtect resolver accepts only a complete HTTPS origin in
`settings.app.baseURL`. It rejects credentials, whitespace, expressions,
non-HTTPS schemes, paths, query strings, fragments, and malformed hosts or
ports. It preserves the supplied authority, including an explicit port, and
appends only the documented GlobalProtect SP paths.
