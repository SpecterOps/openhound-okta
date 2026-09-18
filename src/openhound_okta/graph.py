from dataclasses import dataclass, field
from typing import Final, cast

from openhound.core.models.entries_dataclass import (
    EdgePath as BaseEdgePath,
)
from openhound.core.models.entries_dataclass import (
    Node as BaseNode,
)
from openhound.core.models.entries_dataclass import (
    NodeProperties as BaseProperties,
)

OKTA_SOURCE_KIND: Final[str] = "Okta"
SAML_SOURCE_KIND: Final[str] = "SAML"
SCIM_SOURCE_KIND: Final[str] = "SCIM"


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
    """An Okta-owned node with a per-node source kind for conversion."""

    properties: OktaNodeProperties  # pyright: ignore[reportIncompatibleVariableOverride]
    id: str = field(init=False)

    def __post_init__(self) -> None:
        self.id = self.properties.id.upper()
        # OpenHound does not publish type metadata; its node contract defines
        # ``kinds`` as list[str]. Keep the untyped boundary at this access.
        node_kinds = cast(list[str], getattr(self, "kinds"))
        source_kind = OKTA_SOURCE_KIND
        if any(kind.startswith("SAML_") for kind in node_kinds):
            source_kind = SAML_SOURCE_KIND
        elif any(kind.startswith("SCIM_") for kind in node_kinds):
            source_kind = SCIM_SOURCE_KIND
        if source_kind not in node_kinds:
            self.kinds = [*node_kinds, source_kind]


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
