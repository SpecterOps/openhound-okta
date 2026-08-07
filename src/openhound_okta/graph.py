from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import (
    EdgePath as BaseEdgePath,
)
from openhound.core.models.entries_dataclass import (
    Node as BaseNode,
)
from openhound.core.models.entries_dataclass import (
    NodeProperties as BaseProperties,
)


@dataclass
class OktaNodeProperties(BaseProperties):
    tenant: str
    tenant_domain: str
    id: str

    def __post_init__(self):
        self.name = self.name.upper()
        self.environmentid = self.environmentid.upper()


@dataclass
class OktaNode(BaseNode):
    properties: OktaNodeProperties  # pyright: ignore[reportIncompatibleVariableOverride]
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.properties.id.upper()


@dataclass
class OktaOwnedEdgePath(BaseEdgePath):
    """EdgePath for edges where BOTH endpoints are Okta-owned nodes.

    Okta node ids are uppercased in `OktaNode.__post_init__`, so any edge
    matching by `id` between two Okta nodes must uppercase its value to
    resolve correctly.

    Only import/use this class when matching against a node kind produced
    by THIS collector (i.e. an `OktaNode`). Do NOT use it for edges that
    target another collector's node kind (e.g. Jamf, Snowflake, Azure,
    GitHub) — those collectors have their own id-casing rules, and blindly
    uppercasing here would silently corrupt the match value and break edge
    resolution with no error. Cross-collector edge construction (see
    `hybrid_auth.py`) instead imports the shared `openhound.core.EdgePath`
    and uppercases each foreign-collector target explicitly, on a
    per-target basis, at its construction site.
    """

    def __post_init__(self):
        if self.match_by == "id":
            self.value = self.value.upper()
