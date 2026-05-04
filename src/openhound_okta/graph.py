from dataclasses import dataclass, field

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


@dataclass
class OktaNode(BaseNode):
    properties: OktaNodeProperties  # pyright: ignore[reportIncompatibleVariableOverride]
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.properties.id
