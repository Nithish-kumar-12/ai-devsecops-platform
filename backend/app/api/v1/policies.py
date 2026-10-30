"""
Security Policies & CI/CD Gate API endpoints.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.finding import Finding
from app.models.policy import SecurityPolicy
from app.models.scan import Scan
from app.models.user import User
from app.schemas.policy import GateEvaluationResult, PolicyCreate, PolicyResponse, PolicyUpdate
from app.services.security_gate import SecurityGateEvaluator

router = APIRouter(prefix="/policies", tags=["Security Policies"])


@router.get("", response_model=List[PolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List security gate policies."""
    res = await db.execute(select(SecurityPolicy).order_by(SecurityPolicy.created_at.desc()))
    policies = res.scalars().all()
    return policies


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new CI/CD gate policy."""
    policy = SecurityPolicy(
        name=payload.name,
        project_id=payload.project_id,
        fail_on_critical=payload.fail_on_critical,
        fail_on_high=payload.fail_on_high,
        max_critical=payload.max_critical,
        max_high=payload.max_high,
        max_medium=payload.max_medium,
        block_on_secrets=payload.block_on_secrets,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.post("/evaluate/{scan_id}", response_model=GateEvaluationResult)
async def evaluate_gate(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluates scan findings against project's active security gate policy."""
    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_res.scalars().all()

    # Find policy for project or default global policy
    pol_res = await db.execute(
        select(SecurityPolicy).where(
            (SecurityPolicy.project_id == scan.project_id) | (SecurityPolicy.project_id.is_(None))
        ).order_by(SecurityPolicy.project_id.desc())
    )
    policy = pol_res.scalars().first()

    finding_dicts = [
        {"severity": f.severity, "category": f.category, "status": f.status}
        for f in findings
    ]

    result = SecurityGateEvaluator.evaluate(finding_dicts, policy)

    # Sync result back to scan
    scan.gate_status = result.status
    scan.gate_reason = "; ".join(result.reasons)
    await db.commit()

    return result
