"""
Findings API endpoints — Search, filtering, vulnerability lifecycle, and AI remediation.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingResponse, FindingStatusUpdate
from app.services.ai_remediation import AIRemediationService

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/project/{project_id}", response_model=List[FindingResponse])
async def list_project_findings(
    project_id: str,
    scan_id: Optional[str] = Query(
        None, description="Filter findings to a specific scan"
    ),
    severity: Optional[str] = Query(
        None, description="Filter by severity: critical, high, medium, low"
    ),
    category: Optional[str] = Query(
        None, description="Filter by category: sast, secret, sca, dast"
    ),
    status_filter: Optional[str] = Query(
        None, alias="status", description="Filter by lifecycle status"
    ),
    search: Optional[str] = Query(
        None, description="Search across title, rule_id, file_path, endpoint"
    ),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for a project with dynamic multi-field filtering and sorting."""
    proj_res = await db.execute(
        select(Project).where(Project.id == project_id)
    )
    project = proj_res.scalar_one_or_none()

    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    query = select(Finding).where(Finding.project_id == project_id)

    if scan_id:
        scan_res = await db.execute(
            select(Scan.id).where(
                Scan.id == scan_id,
                Scan.project_id == project_id,
            )
        )
        if scan_res.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Scan not found for project")
        query = query.where(Finding.scan_id == scan_id)

    if severity:
        query = query.where(Finding.severity == severity.lower())

    if category:
        query = query.where(Finding.category == category.lower())

    if status_filter:
        query = query.where(Finding.status == status_filter.lower())

    if search:
        search_term = f"%{search.strip()}%"
        query = query.where(
            or_(
                Finding.title.ilike(search_term),
                Finding.rule_id.ilike(search_term),
                Finding.file_path.ilike(search_term),
                Finding.endpoint.ilike(search_term),
                Finding.package_name.ilike(search_term),
            )
        )

    query = query.order_by(
        Finding.risk_score.desc(),
        Finding.created_at.desc(),
    )

    res = await db.execute(query)
    findings = res.scalars().all()
    return findings


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full details of a finding."""
    res = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = res.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    proj_res = await db.execute(
        select(Project).where(Project.id == finding.project_id)
    )
    project = proj_res.scalar_one_or_none()

    if (
        current_user.role != "admin"
        and project
        and project.owner_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Not authorized")

    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update vulnerability lifecycle state."""
    valid_statuses = {
        "open",
        "in_progress",
        "fixed",
        "retested",
        "closed",
    }
    new_status = payload.status.lower()

    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid status '{payload.status}'. "
                f"Must be one of: {list(valid_statuses)}"
            ),
        )

    res = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = res.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    proj_res = await db.execute(
        select(Project).where(Project.id == finding.project_id)
    )
    project = proj_res.scalar_one_or_none()

    if (
        current_user.role != "admin"
        and project
        and project.owner_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Not authorized")

    finding.status = new_status

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post(
    "/{finding_id}/ai-remediation",
    response_model=FindingResponse,
)
async def generate_ai_remediation(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate an AI-assisted explanation, code-fix guidance,
    and verification steps for a finding.
    """
    res = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = res.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    proj_res = await db.execute(
        select(Project).where(Project.id == finding.project_id)
    )
    project = proj_res.scalar_one_or_none()

    if (
        current_user.role != "admin"
        and project
        and project.owner_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Build the finding context only after authorization succeeds.
    finding_dict = {
        "title": finding.title,
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "description": finding.description,
        "evidence": finding.evidence,
        "scanner": finding.scanner,

        # Source-code location
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "column_number": finding.column_number,

        # Runtime / request context
        "endpoint": finding.endpoint,
        "param": finding.param,

        # Dependency vulnerability context
        "package_name": finding.package_name,
        "package_version": finding.package_version,
        "fixed_version": finding.fixed_version,
        "cve_id": finding.cve_id,

        # Existing remediation and scanner provenance
        "remediation": finding.remediation,
        "raw_payload": finding.raw_payload,
    }

    advice = await AIRemediationService.generate_remediation(finding_dict)

    finding.ai_analysis = advice.get("analysis")
    finding.ai_fix_diff = advice.get("fix_diff")
    finding.ai_verification_steps = advice.get("verification_steps")

    await db.commit()
    await db.refresh(finding)

    return finding
