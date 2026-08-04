from dataclasses import dataclass
from datetime import datetime
import re

from openhound.core.asset import BaseAsset, EdgeDef, NodeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import ConfigDict, Field

from openhound_okta.graph import OktaNode, OktaNodeProperties
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app


@dataclass
class ApiTokenProperties(OktaNodeProperties):
    """Properties for the Okta_ApiToken node"""

    okta_domain: str
    user_id: str
    created: datetime
    client_name: str | None = None
    expires_at: datetime | None = None
    last_updated: datetime | None = None
    network_connection: str | None = None
    token_window: str | None = None


_ISO_DURATION_RE = re.compile(
    r"^P"
    r"(?:(?P<days>\d+)D)?"
    r"(?:T"
    r"(?:(?P<hours>\d+)H)?"
    r"(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+(?:\.\d+)?)S)?"
    r")?$"
)


def token_window_timespan(value: str | None) -> str | None:
    """Convert Okta ISO-8601 token windows to the TimeSpan format OktaHound emits."""
    if value is None:
        return None

    match = _ISO_DURATION_RE.fullmatch(value)
    if not match:
        return value

    days = int(match.group("days") or 0)
    hours = int(match.group("hours") or 0)
    minutes = int(match.group("minutes") or 0)
    seconds = float(match.group("seconds") or 0)
    whole_seconds = int(seconds)
    fraction = seconds - whole_seconds

    prefix = f"{days}." if days else ""
    suffix = f"{prefix}{hours:02}:{minutes:02}:{whole_seconds:02}"
    if fraction:
        suffix += f"{fraction:.7f}"[1:].rstrip("0")
    return suffix


@app.asset(
    description="Okta API token asset",
    node=NodeDef(
        icon="key",
        kind=nk.API_TOKEN,
        description="Okta API token node",
        properties=ApiTokenProperties,
    ),
    edges=[
        EdgeDef(
            start=nk.API_TOKEN,
            end=nk.USER,
            kind=ek.API_TOKEN_FOR,
            description="API token is owned by a user",
            traversable=True,
        )
    ],
)
class ApiToken(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    user_id: str = Field(alias="userId")
    token_window: str | None = Field(alias="tokenWindow", default=None)
    network: dict[str, object] | None = None
    id: str
    client_name: str | None = Field(default=None, alias="clientName")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    created: datetime
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")

    @property
    def as_node(self):
        return OktaNode(
            kinds=[nk.API_TOKEN],
            properties=ApiTokenProperties(
                tenant=self._lookup.org_id(),
                tenant_domain=self._extras["tenant"],
                id=self.id,
                name=self.name,
                displayname=self.name,
                user_id=self.user_id,
                okta_domain=self._extras["tenant"],
                created=self.created,
                client_name=self.client_name,
                expires_at=self.expires_at,
                last_updated=self.last_updated,
                network_connection=self.network.get("connection")
                if self.network
                and isinstance(self.network.get("connection"), str)
                else None,
                token_window=token_window_timespan(self.token_window),
                environmentid=self._lookup.org_id(),
            ),
        )

    @property
    def edges(self):
        yield Edge(
            kind=ek.API_TOKEN_FOR,
            start=EdgePath(value=self.id, match_by="id"),
            end=EdgePath(value=self.user_id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )
