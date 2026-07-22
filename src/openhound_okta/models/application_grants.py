from pydantic import BaseModel, ConfigDict, Field


class ApplicationGrant(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    app_id: str
    scope_id: str | None = Field(default=None, alias="scopeId")
    issuer: str | None = None
