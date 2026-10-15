## Overview

User objects (AKA People) represent individuals who have access to the Okta organization. Each user has a unique identifier, username in the email address format, and various attributes such as email, first name, last name, and status.

Okta users are represented as Okta_User nodes.

## User Status

User status can have [multiple values](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User), as illustrated below:

![Okta user status](https://developer.okta.com/docs/api/images/users/okta-user-status.png)

To simplify analysis in BloodHound, the OpenHound collector maps the **Status** attribute to the virtual boolean **Enabled** attribute as follows:

| Okta User Status | Enabled | Explanation                      |
|------------------|---------|----------------------------------|
| ACTIVE           | ✅     | User can authenticate.           |
| PASSWORD_EXPIRED | ✅     | User's password has expired but can still authenticate. |
| LOCKED_OUT       | ✅     | User is locked out but can still authenticate after unlocking. |
| PROVISIONED      | ✅     | User is provisioned but cannot authenticate yet. |
| RECOVERY         | ✅     | User is in recovery mode and cannot authenticate. |
| SUSPENDED        | ❌     | User is suspended and cannot authenticate. |
| STAGED           | ❌     | User is staged and cannot authenticate yet. |
| DEPROVISIONED    | ❌     | User is deprovisioned and cannot authenticate. |

> [!WARNING]
> This mapping is a simplification and may not cover all edge cases. Always refer to the actual **Status** attribute for precise user state information.

## Authentication Factors

Okta supports various authentication factors for multi-factor authentication (MFA), such as SMS, email, push notifications, and hardware tokens. In case of mobile and desktop applications, these authentication factors are associated with the [Device](Okta_Device.md) entities. Other authentication factors, such as YubiKeys and Google Authenticator, are not represented as separate nodes in BloodHound, but the number of active factors is stored in the `authentication_factors` attribute of the Okta_User nodes. Only factors in the `ACTIVE` status are counted; factors in other states (e.g., `PENDING_ACTIVATION` or `EXPIRED`) are not usable for MFA and are therefore excluded.

Factor enumeration requires one additional API request per user. By default the OpenHound collector fetches factors for every user; in large organizations the `limit_user_mfa_collection` setting restricts collection to privileged users (users with direct role assignments and members of groups that hold admin privileges). The `authentication_factors` attribute is interpreted as follows:

| Value  | Meaning |
|--------|---------|
| `null` | The user's factors were not collected (not privileged while `limit_user_mfa_collection` is enabled, or the request failed). |
| `0`    | The user has no active factors (no usable MFA). |
| `N`    | The user has `N` active factors. |

## Synchronization with External Directories

Users can be synchronized from external directories such as Active Directory (AD) or LDAP. When synchronized, certain attributes may be mapped from the external directory to the Okta user profile.

![Additional Active Directory attributes](../Images/user-ad-attributes.png)
