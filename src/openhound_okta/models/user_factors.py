from pydantic import BaseModel, ConfigDict, Field


class UserFactor(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    user_id: str
    factor_type: str | None = Field(default=None, alias="factorType")
    provider: str | None = None
    status: str | None = None
