"""
Policy Pydantic schemas.
"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class PolicyBase(BaseModel):
    name: str = "Default Gate Policy"
    fail_on_critical: bool = True
    fail_on_high: bool = True
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 5
    block_on_secrets: bool = True


class PolicyCreate(PolicyBase):
    project_id: Optional[str] = None


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    fail_on_critical: Optional[bool] = None
    fail_on_high: Optional[bool] = None
    max_critical: Optional[int] = None
    max_high: Optional[int] = None
    max_medium: Optional[int] = None
    block_on_secrets: Optional[bool] = None


class PolicyResponse(PolicyBase):
    id: str
    project_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GateEvaluationResult(BaseModel):
    passed: bool
    status: str  # "passed", "failed"
    policy_name: str
    reasons: List[str]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    secret_count: int
