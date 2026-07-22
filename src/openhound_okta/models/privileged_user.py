from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from pydantic import BaseModel


class PrivilegedUser(BaseModel):
    """User returned by Okta's privileged assignee inventory endpoint."""

    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
