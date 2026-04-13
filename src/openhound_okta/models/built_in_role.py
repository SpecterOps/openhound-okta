from dataclasses import dataclass
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app

BUILT_IN_ROLES = [
    "API_ACCESS_MANAGEMENT_ADMIN",
    "APP_ADMIN",
    "GROUP_MEMBERSHIP_ADMIN",
    "HELP_DESK_ADMIN",
    "MOBILE_ADMIN",
    "ORG_ADMIN",
    "READ_ONLY_ADMIN",
    "REPORT_ADMIN",
    "SUPER_ADMIN",
    "USER_ADMIN",
    "API_ADMIN",
    "ACCESS_CERTIFICATIONS_ADMIN",
    "ACCESS_REQUEST_ADMIN",
    "WORKFLOWS_ADMIN",
]


@dataclass
class BuiltInRoleProperties(OktaNodeProperties):
    """Properties for the Okta_Role node"""

    is_built_in: bool = True
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
            traversable=False,
        )
    ],
)
class BuiltInRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    type: str

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.ROLE],
            properties=BuiltInRoleProperties(
                tenant=self._lookup.org_id(),
                id=self.type,
                name=self.type,
                displayname=self.type,
                is_built_in=True,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        # The node ID for built-in roles is self.type (e.g. "SUPER_ADMIN"), not a UUID
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.type, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )
