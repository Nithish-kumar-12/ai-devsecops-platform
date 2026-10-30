"""
Scan Pydantic schemas.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict
from app.schemas.finding import FindingResponse


class ScanCreate(BaseModel):
    project_id: str
    scan_type: str = "full"  # "sast", "secrets", "sca", "dast", "full"
    source_type: str = "zip"  # "zip", "git", "url"
    target_label: Optional[str] = None
    target_url: Optional[str] = None
    repository_url: Optional[str] = None
    branch: Optional[str] = "main"
    confirm_authorization: bool = False  # Mandatory confirmation for DAST scans


class ScanResponse(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: str
    source_type: str
    target_label: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    gate_status: str = "pending"
    gate_reason: Optional[str] = None
    error_message: Optional[str] = None
    scanner_details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    findings: List[FindingResponse] = []
