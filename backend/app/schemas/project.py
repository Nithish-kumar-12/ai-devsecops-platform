"""
Project Pydantic schemas.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, HttpUrl


class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None
    repository_url: Optional[str] = None
    target_url: Optional[str] = None
    default_branch: str = "main"


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    repository_url: Optional[str] = None
    target_url: Optional[str] = None
    default_branch: Optional[str] = None


class ProjectResponse(ProjectBase):
    id: str
    owner_id: str
    created_at: datetime
    updated_at: datetime
    total_scans: Optional[int] = 0
    open_findings_count: Optional[int] = 0
    critical_count: Optional[int] = 0
    high_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)
