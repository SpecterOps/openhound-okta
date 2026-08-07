from dataclasses import dataclass
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgeProperties
from pydantic import ConfigDict

from openhound_okta.graph import OktaOwnedEdgePath, OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.built_in_role_permission import BUILT_IN_PERMISSIONS

BUILT_IN_ROLE_METADATA = {
    "API_ACCESS_MANAGEMENT_ADMIN": {
        "label": "API Access Management Administrator",
    },
    "APP_ADMIN": {
        "label": "Application Administrator",
    },
    "GROUP_MEMBERSHIP_ADMIN": {
        "label": "Group Membership Administrator",
    },
    "HELP_DESK_ADMIN": {
        "label": "Help Desk Administrator",
    },
    "MOBILE_ADMIN": {
        "label": "Mobile Administrator",
    },
    "ORG_ADMIN": {
        "label": "Organization Administrator",
    },
    "READ_ONLY_ADMIN": {
        "label": "Read-only Administrator",
    },
    "REPORT_ADMIN": {
        "label": "Report Administrator",
    },
    "SUPER_ADMIN": {
        "label": "Super Administrator",
    },
    "USER_ADMIN": {
        "label": "Group Administrator",
    },
    "WORKFLOWS_ADMIN": {
        "label": "Workflows Administrator",
        "description": "An admin role for managing workflows",
    },
}

BUILT_IN_ROLES = tuple(BUILT_IN_ROLE_METADATA)
UNSUPPORTED_BUILT_IN_ROLES = frozenset(
    {
        "API_ADMIN",
        "ACCESS_CERTIFICATIONS_ADMIN",
        "ACCESS_REQUEST_ADMIN",
        "ACCESS_REQUESTS_ADMIN",
    }
)
SUPPORTED_ROLE_ASSIGNMENT_TYPES = frozenset((*BUILT_IN_ROLES, "CUSTOM"))


def built_in_role_graph_id(role_type: str, tenant_domain: str) -> str:
    """Return the OktaHound-compatible graph ID for a built-in role."""
    return f"{role_type}@{tenant_domain}"


@dataclass
class BuiltInRoleProperties(OktaNodeProperties):
    """Properties for the Okta_Role node"""

    okta_domain: str
    permissions: list[str]
    description: str | None = None


@app.asset(
    description="Okta built-in role asset",
    node=NodeDef(
        icon="clipboard-list",
        kind=nk.ROLE,
        description="Okta built-in role node",
        properties=BuiltInRoleProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.ROLE,
            kind=ek.CONTAINS,
            description="Organization contains built-in role",
            traversable=True,
        )
    ],
)
class BuiltInRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    type: str

    @property
    def as_node(self):
        if self.type not in BUILT_IN_ROLE_METADATA:
            return None

        tenant_domain = self._extras["tenant"]
        role_metadata = BUILT_IN_ROLE_METADATA[self.type]
        role_label = role_metadata["label"]
        return OktaNode(
            kinds=[nk.ROLE],
            properties=BuiltInRoleProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=tenant_domain,
                id=built_in_role_graph_id(self.type, tenant_domain),
                name=role_label,
                displayname=role_label,
                okta_domain=tenant_domain,
                permissions=BUILT_IN_PERMISSIONS.get(self.type, []),
                description=role_metadata.get("description"),
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        if self.type not in BUILT_IN_ROLE_METADATA:
            return

        role_id = built_in_role_graph_id(self.type, self._extras["tenant"])
        yield Edge(
            kind=ek.CONTAINS,
            start=OktaOwnedEdgePath(value=self._lookup.org_id(), match_by="id"),
            end=OktaOwnedEdgePath(value=role_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
