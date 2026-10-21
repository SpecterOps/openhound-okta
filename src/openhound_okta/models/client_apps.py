from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from pydantic import BaseModel, ConfigDict, Field


class JWK(BaseModel):
    """RFC 7517 JSON Web Key as listed in an OAuth 2.0 client's embedded JWKS.

    Unlike the Apps API key objects, these carry no status or timestamps. Keys
    registered through the Apps API also expose their Okta ``id``.
    """

    id: str | None = None
    kid: str | None = None
    kty: str | None = None
    use: str | None = None
    alg: str | None = None
    n: str | None = None
    e: str | None = None


class OauthKeys(BaseModel):
    keys: list[JWK] = Field(default_factory=list)


class ClientApplication(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    client_id: str
    client_id_issued_at: int | None = None
    client_secret_expires_at: int | None = None
    client_name: str | None = None
    client_uri: str | None = None
    logo_uri: str | None = None
    redirect_uris: list[str] = Field(default_factory=list)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    initiate_login_uri: str | None = None
    response_types: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(default_factory=list)
    jwks: OauthKeys | None = None
    token_endpoint_auth_method: str | None = None
    application_type: str
    # Undocumented; set on Okta-managed and OIN-sourced clients.
    software_id: str | None = None
