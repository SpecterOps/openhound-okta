import base64
import binascii
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar
from urllib.parse import urlparse

from dlt.common import json
from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties, ConditionalEdgePath, PropertyMatch
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class GroupProperties(OktaNodeProperties):
    """Properties for the Okta_Group node"""

    okta_domain: str
    okta_group_type: str
    created: datetime
    has_role_assignments: bool = False
    last_updated: datetime | None = None
    last_membership_updated: datetime | None = None
    object_class: str | None = None
    description: str | None = None
    object_sid: str | None = None
    distinguished_name: str | None = None
    sam_account_name: str | None = None
    domain_qualified_name: str | None = None
    group_scope: str | None = None
    group_type: str | None = None
    object_guid: str | None = None


class GroupProfile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    description: str | None = None

    # AD specific fields
    windows_domain_qualified_name: str | None = Field(
        default=None, alias="windowsDomainQualifiedName"
    )
    dn: str | None = None
    external_id: str | None = Field(default=None, alias="externalId")
    sam_account_name: str | None = Field(default=None, alias="samAccountName")
    object_sid: str | None = Field(default=None, alias="objectSid")
    group_scope: str | None = Field(default=None, alias="groupScope")
    group_type: str | None = Field(default=None, alias="groupType")


class Stat(BaseModel):
    users_count: int = Field(alias="usersCount")
    apps_count: int = Field(alias="appsCount")
    has_admin_privilege: bool = Field(alias="hasAdminPrivilege")


class Embedded(BaseModel):
    stats: Stat


class Source(BaseModel):
    id: str


def _decode_object_guid(external_id: str | None) -> str | None:
    if external_id is None:
        return None

    try:
        return str(uuid.UUID(bytes_le=base64.b64decode(external_id, validate=True)))
    except (ValueError, TypeError, binascii.Error):
        return external_id


@app.asset(
    description="Okta group asset",
    node=NodeDef(
        icon="users",
        kind=nk.GROUP,
        description="Okta group node",
        properties=GroupProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.ORG,
            end=nk.GROUP,
            kind=ek.CONTAINS,
            description="Organization contains group",
            traversable=True,
        ),
        EdgeDef(
            start=nk.APPLICATION,
            end=nk.GROUP,
            kind=ek.GROUP_PULL,
            description="Application pulls group from external source",
            traversable=True,
        ),
        EdgeDef(
            start=nk.GROUP,
            end=nk.GROUP,
            kind=ek.MEMBERSHIP_SYNC,
            description="Org2org membership sync",
            traversable=True,
        ),
        EdgeDef(
            start=nk.AD_GROUP,
            end=nk.GROUP,
            kind=ek.MEMBERSHIP_SYNC,
            description="AD membership sync",
            traversable=True,
        ),
    ],
)
class Group(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
    created: datetime
    type: str
    last_membership_updated: datetime | None = Field(
        default=None, alias="lastMembershipUpdated"
    )
    object_class: list[str] = Field(alias="objectClass", default_factory=list)
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    profile: GroupProfile | None = None
    embedded: Embedded = Field(alias="_embedded")
    source: Source | None = None

    @property
    def as_node(self):
        profile_name = self.profile.name if self.profile else None
        object_class = next(iter(self.object_class), None)
        is_active_directory_group = (
            "okta:windows_security_principal" in self.object_class
        )
        return OktaNode(
            kinds=[nk.GROUP],
            properties=GroupProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=profile_name or self.id,
                displayname=profile_name or self.id,
                okta_domain=self._extras["tenant"],
                okta_group_type=self.type,
                created=self.created,
                has_role_assignments=self._lookup.has_role_assignments(
                    self.id, "group"
                ),
                last_updated=self.last_updated,
                last_membership_updated=self.last_membership_updated,
                object_class=object_class,
                description=self.profile.description if self.profile else None,
                object_sid=self.profile.object_sid
                if self.profile and is_active_directory_group
                else None,
                distinguished_name=self.profile.dn
                if self.profile and is_active_directory_group
                else None,
                sam_account_name=self.profile.sam_account_name
                if self.profile and is_active_directory_group
                else None,
                domain_qualified_name=self.profile.windows_domain_qualified_name
                if self.profile and is_active_directory_group
                else None,
                group_scope=self.profile.group_scope
                if self.profile and is_active_directory_group
                else None,
                group_type=self.profile.group_type
                if self.profile and is_active_directory_group
                else None,
                object_guid=_decode_object_guid(self.profile.external_id)
                if self.profile and is_active_directory_group
                else None,
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def _membership_sync_inbound_ad_edge(self):
        if (
            "okta:windows_security_principal" in self.object_class
            and self.profile
            and self.profile.object_sid
        ):
            yield Edge(
                kind=ek.MEMBERSHIP_SYNC,
                start=EdgePath(value=self.profile.object_sid, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _group_pull_edge(self):
        if self.source and self.source.id and self._lookup.application_by_id(self.source.id):
            yield Edge(
                kind=ek.GROUP_PULL,
                start=EdgePath(value=self.source.id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _contains_edges(self):
        yield Edge(
            kind=ek.CONTAINS,
            start=EdgePath(value=self._lookup.org_id(), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _membership_sync_inbound_app_edge(self):
        if (
            self.type == "APP_GROUP"
            and "okta:user_group" in self.object_class
            and self.source
            and self.profile
            and self.profile.name
        ):
            app_settings = self._lookup.application_settings(self.source.id)
            if app_settings:
                app_settings_obj = json.loads(app_settings)
                source_domain = urlparse(app_settings_obj["app"]["baseUrl"]).netloc
                yield Edge(
                    kind=ek.MEMBERSHIP_SYNC,
                    start=ConditionalEdgePath(
                        kind=nk.GROUP, property_matchers=[
                            PropertyMatch(
                                key="tenant_domain", value=source_domain
                            ),
                            PropertyMatch(
                                key="okta_group_type", value="OKTA_GROUP"
                            ),
                            PropertyMatch(
                                key="name", value=self.profile.name.upper()
                            )
                        ]
                    ),
                    end=EdgePath(value=self.id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    @property
    def edges(self):
        yield from self._membership_sync_inbound_app_edge
        yield from self._contains_edges
        yield from self._membership_sync_inbound_ad_edge
        yield from self._group_pull_edge
