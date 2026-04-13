## Overview

Resource sets are collections of entities that can be used to scope custom role assignments in Okta.
A resource set can contain the following object types:

- [x] [Users](Okta_User.md)
- [x] [Groups](Okta_Group.md)
- [x] [Applications](Okta_Application.md)
- [x] [API Service Integrations](Okta_ApiServiceIntegration.md)
- [x] [Devices](Okta_Device.md)
- [x] [Authorization servers](Okta_AuthorizationServer.md)
- [x] [Identity Providers](Okta_IdentityProvider.md)
- [x] [Policies](Okta_Policy.md)
  - [x] Entity risk policy
  - [x] Session protection policy
  - [x] Authentication policy
  - [x] Global session policy
  - [x] End user account management policy
- [ ] Shared Signals Framework (SSF) Receivers
- [ ] ~~Workflows~~ (Gaps in the Okta API)
- [ ] ~~Customizations~~ (Gaps in the Okta API)
- [ ] ~~Support cases~~ (Gaps in the Okta API)
- [ ] ~~Identity and Access Management Resources~~ (Gaps in the Okta API)

> [!NOTE]
> Only the marked resource types are currently supported by `OktaHound` as resource set members.
> Some resource types, such as Workflows, are not accessible via the Okta API at all.

![Okta Resource Set displayed in BloodHound](../Images/bloodhound-resource-set.png)

In `OktaHound`, resource sets are represented as `Okta_ResourceSet` nodes.
