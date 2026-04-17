## Overview

API service integrations in Okta represent OAuth 2.0 service (daemon) applications that can be granted machine-to-machine access to Okta APIs. There are some important differences between API service integrations and [regular OIDC service applications in Okta](Okta_Application.md):

| Feature                                      | Service Applications | API Service Integrations |
|----------------------------------------------|----------------------|--------------------------|
| Can be created manually:                     | ✅                  | ❌                       |
| Can be added from the OIN Catalog:           | ✅                  | ✅                       |
| Require role assignments:                    | ✅                  | ❌                       |
| Support authentication using client secrets: | ✅                  | ✅                       |
| Support authentication using private keys:   | ✅                  | ❌                       |
| Admins can read cleartext client secrets:    | ✅                  | ❌                       |

Okta API service integrations are represented as Okta_ApiServiceIntegration nodes.

## Sample Property Values

```yaml
id: 0oaz7jy5f2oXnvtmN697
name: Falcon Shield
displayName: Falcon Shield
oktaDomain: contoso.okta.com
appType: falconshieldapiservice
oauthScopes:
  - okta.users.read
  - okta.oauthIntegrations.read
  - okta.threatInsights.read
  - okta.devices.read
  - okta.apiTokens.read
  - okta.roles.read
  - okta.logs.read
  - okta.groups.read
  - okta.apps.read
  - okta.domains.read
  - okta.factors.read
  - okta.authenticators.read
  - okta.policies.read
  - okta.networkZones.read
  - okta.features.read
createdAt: 2026-01-15T12:25:42.000Z
```

## Integration OAuth 2.0 Scopes

Each API service integration comes with a pre-defined set of OAuth 2.0 scopes to access Okta APIs:

![Okta API service integration scopes in BloodHound](../Images/bloodhound-api-service-integration-scopes.png)
