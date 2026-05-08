from functools import cache
import json
from pathlib import Path
from typing import Any

ADD_MEMBER = "Okta_AddMember"
AGENT_MEMBER_OF = "Okta_AgentMemberOf"
AGENT_POOL_FOR = "Okta_AgentPoolFor"
API_TOKEN_FOR = "Okta_ApiTokenFor"
APP_ADMIN = "Okta_AppAdmin"
APP_ASSIGNMENT = "Okta_AppAssignment"
CONTAINS = "Okta_Contains"
CREATOR_OF = "Okta_CreatorOf"
DEVICE_OF = "Okta_DeviceOf"
GROUP_ADMIN = "Okta_GroupAdmin"
GROUP_MEMBERSHIP_ADMIN = "Okta_GroupMembershipAdmin"
GROUP_PULL = "Okta_GroupPull"
GROUP_PUSH = "Okta_GroupPush"
HAS_ROLE = "Okta_HasRole"
HAS_ROLE_ASSIGNMENT = "Okta_HasRoleAssignment"
HELPDESK_ADMIN = "Okta_HelpDeskAdmin"
HOSTS_AGENT = "Okta_HostsAgent"
IDENTITY_PROVIDER_FOR = "Okta_IdentityProviderFor"
IDP_GROUP_ASSIGNMENT = "Okta_IdpGroupAssignment"
INBOUND_ORG_SSO = "Okta_InboundOrgSSO"
INBOUND_SSO = "Okta_InboundSSO"
KERBEROS_SSO = "Okta_KerberosSSO"
KEY_OF = "Okta_KeyOf"
MANAGE_APP = "Okta_ManageApp"
MANAGER_OF = "Okta_ManagerOf"
MEMBER_OF = "Okta_MemberOf"
MEMBERSHIP_SYNC = "Okta_MembershipSync"
MOBILE_ADMIN = "Okta_MobileAdmin"
ORG_ADMIN = "Okta_OrgAdmin"
ORG_SWA = "Okta_OrgSWA"
OUTBOUND_ORG_SSO = "Okta_OutboundOrgSSO"
OUTBOUND_SSO = "Okta_OutboundSSO"
POLICY_MAPPING = "Okta_PolicyMapping"
READ_CLIENT_SECRET = "Okta_ReadClientSecret"
READ_PASSWORD_UPDATES = "Okta_ReadPasswordUpdates"
REALM_CONTAINS = "Okta_RealmContains"
RESET_FACTORS = "Okta_ResetFactors"
RESET_PASSWORD = "Okta_ResetPassword"
RESOURCE_SET_CONTAINS = "Okta_ResourceSetContains"
SCOPED_TO = "Okta_ScopedTo"
SECRET_OF = "Okta_SecretOf"
SUPER_ADMIN = "Okta_SuperAdmin"
SWA = "Okta_SWA"
USER_PULL = "Okta_UserPull"
USER_PUSH = "Okta_UserPush"
USER_SYNC = "Okta_UserSync"
PASSWORD_SYNC = "Okta_PasswordSync"

_REPO_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "extension" / "schema.json"
_PACKAGE_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schema.json"


def _schema_path() -> Path:
    for path in (_REPO_SCHEMA_PATH, _PACKAGE_SCHEMA_PATH):
        if path.is_file():
            return path
    raise FileNotFoundError(f"Could not find schema.json at {_REPO_SCHEMA_PATH} or {_PACKAGE_SCHEMA_PATH}")


@cache
def _relationship_traversability() -> dict[str, bool]:
    with _schema_path().open(encoding="utf-8") as schema_file:
        schema: dict[str, Any] = json.load(schema_file)

    return {relationship["name"]: bool(relationship["is_traversable"]) for relationship in schema["relationship_kinds"]}


def traversable(kind: str) -> bool:
    try:
        return _relationship_traversability()[kind]
    except KeyError as error:
        raise KeyError(f"{kind} is not defined in {_schema_path()} relationship_kinds") from error
