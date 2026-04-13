from dataclasses import dataclass
from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class DeviceProperties(OktaNodeProperties):
    """Properties for the Okta_Device node"""

    status: str
    created: datetime
    platform: str
    registered: bool
    last_updated: datetime | None = None
    manufacturer: str | None = None
    model: str | None = None
    os_version: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    jailbreak: bool | None = None


class DisplayName(BaseModel):
    value: str
    sensitive: bool


class Profile(BaseModel):
    display_name: str = Field(alias="displayName")
    platform: str
    manufacturer: str | None = None
    model: str | None = None
    os_version: str | None = Field(default=None, alias="osVersion")
    registered: bool
    secure_hardware_present: bool | None = Field(
        default=None, alias="secureHardwarePresent"
    )
    integrity_jailbreak: bool | None = Field(default=None, alias="integrityJailbreak")
    authenticator_app_key: str | None = Field(default=None, alias="authenticatorAppKey")


class UserDetails(BaseModel):
    id: str
    realm_id: str = Field(alias="realmId")


class EmbeddedUser(BaseModel):
    created: datetime | None = None
    user: UserDetails


class Embedded(BaseModel):
    users: list[EmbeddedUser] = Field(default_factory=list)


@app.asset(
    description="Okta device asset",
    node=NodeDef(
        icon="mobile",
        kind=nk.DEVICE,
        description="Okta device node",
        properties=DeviceProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.DEVICE,
            kind=ek.CONTAINS,
            description="Organization contains device",
            traversable=False,
        ),
        EdgeDef(
            start=nk.DEVICE,
            end=nk.USER,
            kind=ek.DEVICE_OF,
            description="Device belongs to user",
            traversable=False,
        ),
    ],
)
class Device(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    status: str
    created: datetime
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    profile: Profile  # | None = None
    resource_type: str | None = Field(default=None, alias="resourceType")
    resource_display_name: DisplayName | None = Field(
        default=None, alias="resourceDisplayName"
    )
    resource_id: str = Field(alias="resourceId")
    embedded: Embedded | None = Field(default=None, alias="_embedded")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.DEVICE],
            properties=DeviceProperties(
                tenant=self._lookup.org_id(),
                id=self.id,
                name=self.profile.display_name,
                displayname=self.profile.display_name,
                status=self.status,
                created=self.created,
                last_updated=self.last_updated,
                platform=self.profile.platform,
                manufacturer=self.profile.manufacturer,
                model=self.profile.model,
                registered=self.profile.registered,
                jailbreak=self.profile.integrity_jailbreak,
                os_version=self.profile.os_version,
                resource_type=self.resource_type,
                resource_id=self.resource_id,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _device_of_edges(self):
        if self.embedded:
            for user in self.embedded.users:
                yield Edge(
                    kind=ek.DEVICE_OF,
                    start=EdgePath(value=self.id, match_by="id"),
                    end=EdgePath(value=user.user.id, match_by="id"),
                    properties=EdgeProperties(traversable=False),
                )

    @property
    def _contains_edge(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=False),
        )

    @property
    def edges(self):
        yield from self._contains_edge
        yield from self._device_of_edges
