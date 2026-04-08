## Overview

Identity Providers (IdPs) in Okta represent external authentication sources that can be used to authenticate users. These can include social identity providers (such as Google, Facebook, or Microsoft), enterprise identity providers using SAML or OIDC, or other Okta organizations in an Org2Org configuration.

When users authenticate through an external identity provider, Okta can optionally create or link user accounts, enabling federated authentication across multiple systems.

In `OktaHound`, identity providers are represented as `Okta_IdentityProvider` nodes.

> [!WARNING]
> The inbound identity provider routing rules and JIT (Just-In-Time) provisioning settings are currently not evaluated by `OktaHound`.

## Sample Property Values

```yaml
id: 0oazpi53t1cRNcPL4697
name: Microsoft Entra ID
displayName: Microsoft Entra ID
oktaDomain: contoso.okta.com
created: 2026-01-31T15:21:37+00:00
issuerMode: DYNAMIC
type: MICROSOFT
enabled: false
autoUserProvisioning: true
governedGroupIds: []
protocolType: OIDC
url: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
```
