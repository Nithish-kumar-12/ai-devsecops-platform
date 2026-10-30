"""
Projects API endpoints — CRUD operations and statistics.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectResponse, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["Projects"])


@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List projects accessible to the current user with aggregated metrics."""
    query = select(Project)
    if current_user.role != "admin":
        query = query.where(Project.owner_id == current_user.id)
    query = query.order_by(Project.created_at.desc())

    res = await db.execute(query)
    projects = res.scalars().all()

    results = []
    for p in projects:
        # Aggregate scans count
        scan_count_res = await db.execute(
            select(func.count(Scan.id)).where(Scan.project_id == p.id)
        )
        total_scans = scan_count_res.scalar() or 0

        # Aggregate open findings count
        open_findings_res = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == p.id,
                Finding.status.in_(["open", "in_progress"])
            )
        )
        open_findings = open_findings_res.scalar() or 0

        # Aggregate critical and high
        crit_res = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == p.id,
                Finding.status.in_(["open", "in_progress"]),
                Finding.severity == "critical"
            )
        )
        crit_count = crit_res.scalar() or 0

        high_res = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == p.id,
                Finding.status.in_(["open", "in_progress"]),
                Finding.severity == "high"
            )
        )
        high_count = high_res.scalar() or 0

        p_dict = ProjectResponse.model_validate(p)
        p_dict.total_scans = total_scans
        p_dict.open_findings_count = open_findings
        p_dict.critical_count = crit_count
        p_dict.high_count = high_count
        results.append(p_dict)

    return results


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new security scanning project."""
    project = Project(
        name=payload.name,
        description=payload.description,
        owner_id=current_user.id,
        repository_url=str(payload.repository_url) if payload.repository_url else None,
        target_url=str(payload.target_url) if payload.target_url else None,
        default_branch=payload.default_branch,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get project details by ID."""
    res = await db.execute(select(Project).where(Project.id == project_id))
    project = res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Counts
    scan_count_res = await db.execute(select(func.count(Scan.id)).where(Scan.project_id == project.id))
    open_findings_res = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.project_id == project.id, Finding.status.in_(["open", "in_progress"])
        )
    )
    crit_res = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.project_id == project.id,
            Finding.status.in_(["open", "in_progress"]),
            Finding.severity == "critical",
        )
    )
    high_res = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.project_id == project.id,
            Finding.status.in_(["open", "in_progress"]),
            Finding.severity == "high",
        )
    )

    resp = ProjectResponse.model_validate(project)
    resp.total_scans = scan_count_res.scalar() or 0
    resp.open_findings_count = open_findings_res.scalar() or 0
    resp.critical_count = crit_res.scalar() or 0
    resp.high_count = high_res.scalar() or 0
    return resp


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update project metadata."""
    res = await db.execute(select(Project).where(Project.id == project_id))
    project = res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to modify this project")

    if payload.name is not None:
        project.name = payload.name
    if payload.description is not None:
        project.description = payload.description
    if payload.repository_url is not None:
        project.repository_url = str(payload.repository_url) if payload.repository_url else None
    if payload.target_url is not None:
        project.target_url = str(payload.target_url) if payload.target_url else None
    if payload.default_branch is not None:
        project.default_branch = payload.default_branch

    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a project and all associated scans and findings."""
    res = await db.execute(select(Project).where(Project.id == project_id))
    project = res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this project")

    await db.delete(project)
    await db.commit()
