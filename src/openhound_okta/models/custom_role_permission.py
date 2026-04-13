from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime


class CustomRolePermission(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    label: str
    created: datetime | None = None
    last_updated: str | None = Field(default=None, alias="lastUpdated")
    conditions: dict | None = None
    links: dict | None = Field(default=None, alias="_links")

    # Custom fields for easier querying
    role_id: str
    role_label: str
