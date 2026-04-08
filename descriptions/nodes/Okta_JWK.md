## Overview

JSON Web Keys (JWKs) are used by OAuth 2.0 client applications to authenticate with Okta using the `private_key_jwt` client authentication method.
This is an asymmetric authentication mechanism where the application possesses a private key and Okta stores the corresponding public key.
A service application can have multiple JWKs configured for key rotation purposes.

JWKs are represented as `Okta_JWK` nodes in BloodHound.

## Sample Property Values

```yaml
id: pksw0py294dQ80EdI697
name: ncxmNARybDrxlemwkrvyphCYQ2VwMG9cxV95jgVziZ4
displayName: ncxmNARybDrxlemwkrvyphCYQ2VwMG9cxV95jgVziZ4
oktaDomain: contoso.okta.com
status: ACTIVE
kid: ncxmNARybDrxlemwkrvyphCYQ2VwMG9cxV95jgVziZ4
kty: RSA
use: sig
created: 2025-10-02T10:14:44Z
lastUpdated: 2025-10-02T10:26:27Z
```
