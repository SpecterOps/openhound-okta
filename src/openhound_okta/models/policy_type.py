from pydantic import BaseModel


class PolicyType(BaseModel):
    policy_type: str
