from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from pydantic import BaseModel


class PrivilegedUser(BaseModel):
    """User returned by Okta's privileged assignee inventory endpoint.

    Also the id-only carrier for admin-group members in the limited-mode
    factor stream (see source.admin_group_members).
    """

    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    id: str
