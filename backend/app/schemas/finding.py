"""
Finding Pydantic schemas.
"""
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict


class FindingBase(BaseModel):
    rule_id: str
    title: str
    description: str
    category: str  # "sast", "secret", "sca", "dast", "iac"
    severity: str  # "critical", "high", "medium", "low"
    confidence: str = "unknown"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    endpoint: Optional[str] = None
    param: Optional[str] = None
    evidence: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None


class FindingCreate(FindingBase):
    project_id: str
    scan_id: str
    scanner: str
    raw_payload: Optional[Dict[str, Any]] = None


class FindingStatusUpdate(BaseModel):
    status: str  # "open", "in_progress", "fixed", "retested", "closed"


class FindingAIAnalysisUpdate(BaseModel):
    ai_analysis: str
    ai_fix_diff: Optional[str] = None
    ai_verification_steps: Optional[str] = None


class FindingResponse(FindingBase):
    id: str
    project_id: str
    scan_id: str
    scanner: str
    status: str
    risk_score: float
    correlation_group_id: Optional[str] = None
    correlation_reason: Optional[str] = None
    ai_analysis: Optional[str] = None
    ai_fix_diff: Optional[str] = None
    ai_verification_steps: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
