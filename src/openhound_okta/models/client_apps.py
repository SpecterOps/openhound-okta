from datetime import datetime
from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from pydantic import BaseModel, ConfigDict, Field


class JWK(BaseModel):
    kid: str
    status: str | None = None
    last_updated: datetime | None = Field(default=None, alias="lastUpdated")
    created: datetime | None = None


class OauthKeys(BaseModel):
    keys: list[JWK] = Field(default_factory=list)


class ClientApplication(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    client_id: str
    client_id_issued_at: int
    client_secret_expires_at: int | None = None
    response_types: list[str]
    grant_types: list[str]
    jwks: OauthKeys | None = None
    token_endpoint_auth_method: str
    application_type: str
