"""
Scans API endpoints — Trigger scans via ZIP upload, Git repo, or DAST URL.
"""
import os
import shutil
import tempfile
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.core.config import settings
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanCreate, ScanDetailResponse, ScanResponse
from app.services.safe_archive import ArchiveSecurityError, SafeArchiveService
from app.services.scan_orchestrator import ScanOrchestrator

router = APIRouter(prefix="/scans", tags=["Scans"])


def build_scan_detail_response(scan: Scan, findings: List[Finding]) -> ScanDetailResponse:
    findings_dto = [FindingResponse.model_validate(f) for f in findings]
    return ScanDetailResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        source_type=scan.source_type,
        target_label=scan.target_label,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        gate_status=scan.gate_status,
        gate_reason=scan.gate_reason,
        error_message=scan.error_message,
        scanner_details=scan.scanner_details,
        created_at=scan.created_at,
        findings=findings_dto,
    )


@router.post("/upload-and-scan", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_scan(
    project_id: str = Form(...),
    scan_type: str = Form("full"),
    confirm_authorization: bool = Form(False),
    target_url_override: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Unified scan endpoint. Behaviour depends on scan_type:

    - sast / secrets / sca / full : require a .zip source archive (file is mandatory).
    - dast                        : no ZIP required; uses target_url from the project
                                    or target_url_override form field. Requires
                                    confirm_authorization=true.

    Upload limit: settings.MAX_UPLOAD_SIZE_BYTES (default 1 GiB).
    Files are streamed in 64 KiB chunks — never fully loaded into RAM.
    """
    # 1. Verify project access
    proj_res = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this project")

    # -------------------------------------------------------------------------
    # A. DAST-ONLY — no ZIP upload required
    # -------------------------------------------------------------------------
    if scan_type == "dast":
        if not confirm_authorization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Explicit target authorization is required before launching DAST scans.",
            )

        effective_target_url = target_url_override or project.target_url
        if not effective_target_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "DAST scan requires a target URL. "
                    "Either set a Target DAST URL on the project or supply target_url_override."
                ),
            )

        scan = Scan(
            project_id=project.id,
            triggered_by_id=current_user.id,
            scan_type="dast",
            status="pending",
            source_type="url",
            target_label=effective_target_url,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        completed_scan = await ScanOrchestrator.run_scan_pipeline(
            db=db,
            scan_id=scan.id,
            target_path=None,
            target_url=effective_target_url,
            confirm_authorization=True,
        )

        findings_res = await db.execute(
            select(Finding).where(Finding.scan_id == completed_scan.id).order_by(Finding.risk_score.desc())
        )
        findings = findings_res.scalars().all()
        return build_scan_detail_response(completed_scan, findings)

    # -------------------------------------------------------------------------
    # B. Code-based scans (sast / secrets / sca / full) — ZIP file required
    # -------------------------------------------------------------------------
    if file is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"A .zip source-code archive is required for '{scan_type}' scans. "
                "Only DAST-only scans can run without a ZIP file."
            ),
        )

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only valid .zip archives are supported for source uploads.",
        )

    # 3. Stream the upload to a temp file — never read entire file into RAM
    temp_dir = tempfile.mkdtemp(prefix="devsecops_upload_")
    zip_dest = os.path.join(temp_dir, "source.zip")
    extracted_dest = os.path.join(temp_dir, "extracted")

    max_bytes = settings.MAX_UPLOAD_SIZE_BYTES  # 1 GiB default
    max_mb = settings.effective_max_upload_mb

    try:
        total_read = 0
        with open(zip_dest, "wb") as fout:
            while True:
                chunk = await file.read(65536)  # 64 KiB streaming chunks
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=(
                            f"Uploaded ZIP exceeds the maximum allowed size of "
                            f"{max_mb} MiB ({max_bytes:,} bytes). "
                            "Compress the archive or exclude build artefacts (node_modules, .git, venv)."
                        ),
                    )
                fout.write(chunk)

        # 4. Safely extract archive with Zip Slip, Bomb, and Traversal protection
        try:
            file_count, uncompressed_size = SafeArchiveService.validate_and_extract(
                zip_dest, extracted_dest
            )
        except ArchiveSecurityError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security violation in uploaded archive: {str(e)}",
            )

        # 5. Create Scan DB record
        scan = Scan(
            project_id=project.id,
            triggered_by_id=current_user.id,
            scan_type=scan_type,
            status="pending",
            source_type="zip",
            target_label=file.filename,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        # 6. Execute Scan Orchestration pipeline
        effective_target_url = (
            target_url_override or project.target_url
            if scan_type == "full"
            else None
        )
        completed_scan = await ScanOrchestrator.run_scan_pipeline(
            db=db,
            scan_id=scan.id,
            target_path=extracted_dest,
            target_url=effective_target_url,
            confirm_authorization=confirm_authorization,
        )

        # 7. Fetch findings
        findings_res = await db.execute(
            select(Finding).where(Finding.scan_id == completed_scan.id).order_by(Finding.risk_score.desc())
        )
        findings = findings_res.scalars().all()

        return build_scan_detail_response(completed_scan, findings)

    finally:
        # Safe cleanup of all temporary extracted source files
        SafeArchiveService.cleanup(temp_dir)



@router.post("/trigger", response_model=ScanDetailResponse, status_code=status.HTTP_201_CREATED)
async def trigger_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger scan for configured Git repository or authorized DAST endpoint.
    Supports DAST-only scans (no source code required) and future Git-repo scans.
    """
    proj_res = await db.execute(select(Project).where(Project.id == payload.project_id))
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this project")

    target_url = payload.target_url or project.target_url

    if payload.scan_type in ("dast", "full"):
        if not payload.confirm_authorization:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Explicit target authorization is required before launching DAST scans.",
            )
        if not target_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "DAST scan requires a target URL. "
                    "Set a Target DAST URL on the project or pass target_url in the request body."
                ),
            )

    scan = Scan(
        project_id=project.id,
        triggered_by_id=current_user.id,
        scan_type=payload.scan_type,
        status="pending",
        source_type=payload.source_type,
        target_label=payload.target_label or target_url or project.repository_url or "Dynamic target",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    completed_scan = await ScanOrchestrator.run_scan_pipeline(
        db=db,
        scan_id=scan.id,
        target_path=None,
        target_url=target_url,
        confirm_authorization=payload.confirm_authorization,
    )

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == completed_scan.id).order_by(Finding.risk_score.desc())
    )
    findings = findings_res.scalars().all()

    return build_scan_detail_response(completed_scan, findings)


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_details(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve detailed scan metrics and findings."""
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check project ownership
    proj_res = await db.execute(select(Project).where(Project.id == scan.project_id))
    project = proj_res.scalar_one_or_none()
    if current_user.role != "admin" and project and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.risk_score.desc())
    )
    findings = findings_res.scalars().all()

    return build_scan_detail_response(scan, findings)


@router.get("/project/{project_id}", response_model=List[ScanResponse])
async def list_project_scans(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List historical scans for a project."""
    proj_res = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized")

    scans_res = await db.execute(
        select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
    )
    scans = scans_res.scalars().all()
    return scans


@router.post("/github-action", status_code=status.HTTP_201_CREATED)
async def github_action_scan(
    project_id: str = Form(...),
    scan_type: str = Form("full"),
    source: UploadFile = File(...),
    commit_sha: Optional[str] = Form(None),
    branch: Optional[str] = Form(None),
    repository: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    CI/CD endpoint for GitHub Actions workflow.
    Safely receives source.zip, executes security scan pipeline, and returns scan_id.
    """
    # 1. Verify project access
    proj_res = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_res.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if current_user.role != "admin" and project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to scan this project")

    temp_dir = tempfile.mkdtemp(prefix="github_action_")
    zip_dest = os.path.join(temp_dir, "source.zip")
    extracted_dest = os.path.join(temp_dir, "extracted")

    try:
        max_bytes = settings.MAX_UPLOAD_SIZE_BYTES
        total_read = 0

        with open(zip_dest, "wb") as f:
            while chunk := await source.read(1024 * 64):
                total_read += len(chunk)
                if total_read > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="Archive exceeds size limit",
                    )
                f.write(chunk)

        try:
            SafeArchiveService.validate_and_extract(zip_dest, extracted_dest)
        except ArchiveSecurityError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security violation in CI archive: {str(e)}",
            )

        label = f"CI: {repository or 'repo'}@{branch or 'main'} ({commit_sha[:7] if commit_sha else 'head'})"
        scan = Scan(
            project_id=project.id,
            triggered_by_id=current_user.id,
            scan_type=scan_type,
            status="pending",
            source_type="zip",
            target_label=label,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        completed_scan = await ScanOrchestrator.run_scan_pipeline(
            db=db,
            scan_id=scan.id,
            target_path=extracted_dest,
            target_url=project.target_url if scan_type in ("dast", "full") else None,
            confirm_authorization=True,
        )

        return {
            "scan_id": completed_scan.id,
            "status": completed_scan.status,
            "gate_status": completed_scan.gate_status,
            "critical_count": completed_scan.critical_count,
            "high_count": completed_scan.high_count,
        }

    finally:
        SafeArchiveService.cleanup(temp_dir)


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lightweight status polling endpoint for CI/CD runners."""
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project_res = await db.execute(select(Project).where(Project.id == scan.project_id))
    project = project_res.scalar_one_or_none()
    if (
        current_user.role != "admin"
        and project
        and project.owner_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "gate_status": scan.gate_status,
    }


@router.get("/{scan_id}/gate-result")
async def get_scan_gate_result(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve CI/CD security gate pass/fail decision and violation details."""
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project_res = await db.execute(select(Project).where(Project.id == scan.project_id))
    project = project_res.scalar_one_or_none()
    if (
        current_user.role != "admin"
        and project
        and project.owner_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    violations = []
    if scan.gate_status != "passed" and scan.gate_reason:
        violations = [r.strip() for r in scan.gate_reason.split(";") if r.strip()]

    return {
        "scan_id": scan.id,
        "passed": scan.gate_status == "passed",
        "status": scan.gate_status,
        "violations": violations,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
    }
