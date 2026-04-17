## Overview

Client secrets are used by API service integrations and OIDC applications to authenticate with Okta and obtain access tokens.

![Okta client secret creation](../Images/app-client-secret-creation.png)

An application can have up to two client secrets configured, to allow for secret rotation.

![Okta client secret rotation](../Images/app-client-secret-rotation.png)

Client secrets are represented as Okta_ClientSecret nodes in BloodHound.

> [!NOTE]
> For security reasons, the OpenHound and OktaHound collectors do not collect client secrets, only their hashed identifiers.

## Sample Property Values

```yaml
id: ocsxqwizfyqsf0aVG697
name: T1e6fl4jGqvPkgd94NKx5g
displayName: T1e6fl4jGqvPkgd94NKx5g
oktaDomain: contoso.okta.com
status: ACTIVE
created: 2025-11-24T12:24:08.000Z
lastUpdated: 2025-11-24T12:24:08.000Z
```
