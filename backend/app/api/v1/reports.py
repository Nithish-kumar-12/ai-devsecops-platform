"""
Reports, Exports, and Audit Log API endpoints.
Provides system metrics, JSON and CSV exports of scan findings.
"""
import csv
import io
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Response, status
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User

router = APIRouter(prefix="/reports", tags=["Reports & Analytics"])


@router.get("/metrics")
async def get_dashboard_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Retrieve aggregate security analytics for dashboard overview."""
    # Project count
    proj_query = select(func.count(Project.id))
    if current_user.role != "admin":
        proj_query = proj_query.where(Project.owner_id == current_user.id)
    proj_res = await db.execute(proj_query)
    total_projects = proj_res.scalar() or 0

    # Scan counts
    scan_query = select(func.count(Scan.id))
    if current_user.role != "admin":
        scan_query = scan_query.join(Project).where(Project.owner_id == current_user.id)
    scan_res = await db.execute(scan_query)
    total_scans = scan_res.scalar() or 0

    # Gate passed / failed
    gate_query = select(Scan.gate_status, func.count(Scan.id))
    if current_user.role != "admin":
        gate_query = gate_query.join(Project).where(Project.owner_id == current_user.id)
    gate_query = gate_query.group_by(Scan.gate_status)
    gate_res = await db.execute(gate_query)
    gate_stats = dict(gate_res.all())

    # Active Open Findings by severity (immediate remediation required)
    sev_query = select(Finding.severity, func.count(Finding.id)).where(
        Finding.status.in_(["open", "in_progress"])
    )
    if current_user.role != "admin":
        sev_query = sev_query.join(Project).where(Project.owner_id == current_user.id)
    sev_query = sev_query.group_by(Finding.severity)
    sev_res = await db.execute(sev_query)
    sev_stats = dict(sev_res.all())

    # Total all-time findings count across all states
    total_findings_query = select(func.count(Finding.id))
    if current_user.role != "admin":
        total_findings_query = total_findings_query.join(Project).where(Project.owner_id == current_user.id)
    total_findings_res = await db.execute(total_findings_query)
    total_findings = total_findings_res.scalar() or 0

    # Findings by category
    cat_query = select(Finding.category, func.count(Finding.id))
    if current_user.role != "admin":
        cat_query = cat_query.join(Project).where(Project.owner_id == current_user.id)
    cat_query = cat_query.group_by(Finding.category)
    cat_res = await db.execute(cat_query)
    cat_stats = dict(cat_res.all())

    # Recent scans
    recent_query = select(Scan).order_by(Scan.created_at.desc()).limit(5)
    if current_user.role != "admin":
        recent_query = recent_query.join(Project).where(Project.owner_id == current_user.id)
    recent_res = await db.execute(recent_query)
    recent_scans = recent_res.scalars().all()

    return {
        "total_projects": total_projects,
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_counts": {
            "critical": sev_stats.get("critical", 0),
            "high": sev_stats.get("high", 0),
            "medium": sev_stats.get("medium", 0),
            "low": sev_stats.get("low", 0),
        },
        "category_counts": cat_stats,
        "gate_status_counts": {
            "passed": gate_stats.get("passed", 0),
            "failed": gate_stats.get("failed", 0),
            "pending": gate_stats.get("pending", 0),
        },
        "recent_scans": [
            {
                "id": s.id,
                "project_id": s.project_id,
                "scan_type": s.scan_type,
                "status": s.status,
                "gate_status": s.gate_status,
                "created_at": s.created_at.isoformat(),
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
            }
            for s in recent_scans
        ],
    }


@router.get("/export/json/{scan_id}")
async def export_scan_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download scan results and findings as machine-readable JSON."""
    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_res.scalar_one_or_none()
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

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_res.scalars().all()

    report = {
        "platform": "AI DevSecOps Platform",
        "scan_id": scan.id,
        "project_id": scan.project_id,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "gate_status": scan.gate_status,
        "gate_reason": scan.gate_reason,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "total": len(findings),
        },
        "findings": [
            {
                "id": f.id,
                "scanner": f.scanner,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "location": {
                    "file_path": f.file_path,
                    "line": f.line_number,
                    "column": f.column_number,
                    "endpoint": f.endpoint,
                    "param": f.param,
                },
                "package": {
                    "name": f.package_name,
                    "version": f.package_version,
                    "fixed_version": f.fixed_version,
                    "cve": f.cve_id,
                },
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status,
                "risk_score": f.risk_score,
                "correlation_group_id": f.correlation_group_id,
            }
            for f in findings
        ],
    }

    return report


@router.get("/export/csv/{scan_id}")
async def export_scan_csv(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download scan findings as a CSV file."""
    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_res.scalar_one_or_none()
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

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
    )
    findings = findings_res.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID",
        "Scanner",
        "Rule ID",
        "Severity",
        "Category",
        "Title",
        "File / Endpoint",
        "Line",
        "Status",
        "Risk Score",
        "Remediation",
    ])

    for f in findings:
        loc = f.file_path or f.endpoint or "N/A"
        writer.writerow([
            f.id,
            f.scanner,
            f.rule_id,
            f.severity.upper(),
            f.category.upper(),
            f.title,
            loc,
            f.line_number or "N/A",
            f.status.upper(),
            f.risk_score,
            (f.remediation or "").replace("\n", " "),
        ])

    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=security_scan_{scan_id}.csv"},
    )


@router.get("/export/pdf/{scan_id}")
async def export_scan_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download a PDF scan report with scope, timestamps, findings, and gate result."""
    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_res.scalar_one_or_none()
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

    findings_res = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
    )
    findings = findings_res.scalars().all()

    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter, title=f"Security Scan {scan_id}")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("AI DevSecOps Platform - Security Scan Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Scan ID: {scan.id}", styles["BodyText"]),
        Paragraph(f"Project ID: {scan.project_id}", styles["BodyText"]),
        Paragraph(f"Project: {project.name if project else 'Unknown'}", styles["BodyText"]),
        Paragraph(f"Scan type: {scan.scan_type}", styles["BodyText"]),
        Paragraph(f"Source: {scan.source_type}", styles["BodyText"]),
        Paragraph(f"Target or label: {scan.target_label or 'N/A'}", styles["BodyText"]),
        Paragraph(f"Started: {scan.started_at.isoformat() if scan.started_at else 'N/A'}", styles["BodyText"]),
        Paragraph(f"Completed: {scan.completed_at.isoformat() if scan.completed_at else 'N/A'}", styles["BodyText"]),
        Spacer(1, 8),
        Paragraph("Security Gate", styles["Heading2"]),
        Paragraph(f"Status: {scan.gate_status}", styles["BodyText"]),
        Paragraph(f"Reason: {scan.gate_reason or 'No policy violation recorded'}", styles["BodyText"]),
        Paragraph(
            f"Severity summary: Critical {scan.critical_count}, High {scan.high_count}, "
            f"Medium {scan.medium_count}, Low {scan.low_count}, Total {len(findings)}",
            styles["BodyText"],
        ),
        Spacer(1, 10),
        Paragraph("Findings", styles["Heading2"]),
    ]

    if findings:
        table_data = [["Severity", "Title", "Scanner", "Location", "Status"]]
        for finding in findings:
            location = finding.file_path or finding.endpoint or finding.package_name or "N/A"
            if finding.line_number:
                location = f"{location}:{finding.line_number}"
            table_data.append([
                finding.severity.upper(),
                Paragraph(finding.title[:160], styles["BodyText"]),
                finding.scanner,
                Paragraph(location[:180], styles["BodyText"]),
                finding.status,
            ])
        table = Table(table_data, colWidths=[50, 180, 65, 110, 55])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No findings were recorded for this scan.", styles["BodyText"]))

    document.build(story)
    pdf_content = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=security_scan_{scan_id}.pdf"},
    )
