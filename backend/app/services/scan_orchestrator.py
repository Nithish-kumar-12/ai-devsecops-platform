"""
Scan Orchestrator Service.
Coordinates execution of SAST, Secrets, SCA, and DAST scans, applies correlation,
risk scoring, and CI/CD security gate evaluation, and persists findings to DB.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.finding import Finding
from app.models.policy import SecurityPolicy
from app.models.project import Project
from app.models.scan import Scan
from app.pipeline.correlation import CorrelationEngine
from app.pipeline.risk_prioritizer import RiskPrioritizer
from app.scanners.dependency_scanner import DependencyScanner
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.zap_dast_scanner import ZapDastScanner
from app.services.security_gate import SecurityGateEvaluator

logger = structlog.get_logger(__name__)


class ScanOrchestrator:
    @classmethod
    async def run_scan_pipeline(
        cls,
        db: AsyncSession,
        scan_id: str,
        target_path: Optional[str] = None,
        target_url: Optional[str] = None,
        confirm_authorization: bool = False,
    ) -> Scan:
        """
        Executes end-to-end scan pipeline for scan_id.
        """
        # 1. Fetch scan record
        res = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = res.scalar_one_or_none()
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found.")

        # Update status to running
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(scan)

        raw_findings: List[Dict[str, Any]] = []
        scanner_info: Dict[str, Any] = {}

        try:
            # Execute scanners based on scan_type
            scan_type = scan.scan_type.lower()

            # SAST Scan
            if scan_type in ("sast", "full") and target_path:
                semgrep = SemgrepScanner()
                scanner_info["semgrep"] = {"available": semgrep.is_available()}
                if semgrep.is_available():
                    sast_findings = await semgrep.scan(target_path)
                    raw_findings.extend(sast_findings)

            # Secret Scan
            if scan_type in ("secrets", "full") and target_path:
                gitleaks = GitleaksScanner()
                scanner_info["gitleaks"] = {"available": gitleaks.is_available()}
                secret_findings = await gitleaks.scan(target_path)
                raw_findings.extend(secret_findings)

            # SCA Dependency Scan
            if scan_type in ("sca", "full") and target_path:
                sca = DependencyScanner()
                scanner_info["osv_scanner"] = {"available": sca.is_available()}
                sca_findings = await sca.scan(target_path)
                raw_findings.extend(sca_findings)

            # DAST Scan
            if scan_type in ("dast", "full") and target_url:
                dast = ZapDastScanner()
                scanner_info["zap"] = {"available": dast.is_available()}
                dast_findings = await dast.scan(
                    target_url,
                    confirm_authorization=confirm_authorization,
                )
                raw_findings.extend(dast_findings)

            # 2. Correlate findings across vectors
            correlated = CorrelationEngine.correlate_findings(raw_findings)

            # 3. Prioritize findings & compute risk scores
            prioritized = RiskPrioritizer.prioritize_findings(correlated)

            # 4. Fetch applicable policy
            policy_res = await db.execute(
                select(SecurityPolicy).where(
                    (SecurityPolicy.project_id == scan.project_id)
                    | (SecurityPolicy.project_id.is_(None))
                ).order_by(SecurityPolicy.project_id.desc())
            )
            policy = policy_res.scalars().first()

            # 5. Evaluate CI/CD security gate
            gate_res = SecurityGateEvaluator.evaluate(prioritized, policy)

            # 6. Save findings to database
            crit_count = 0
            high_count = 0
            med_count = 0
            low_count = 0

            for f_data in prioritized:
                sev = f_data.get("severity", "medium").lower()
                if sev == "critical":
                    crit_count += 1
                elif sev == "high":
                    high_count += 1
                elif sev == "medium":
                    med_count += 1
                elif sev == "low":
                    low_count += 1

                finding_obj = Finding(
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    scanner=f_data.get("scanner", "unknown"),
                    rule_id=f_data.get("rule_id", "rule"),
                    title=f_data.get("title", "Untitled finding"),
                    description=f_data.get("description", ""),
                    category=f_data.get("category", "sast"),
                    severity=sev,
                    confidence=f_data.get("confidence", "unknown"),
                    file_path=f_data.get("file_path"),
                    line_number=f_data.get("line_number"),
                    column_number=f_data.get("column_number"),
                    endpoint=f_data.get("endpoint"),
                    param=f_data.get("param"),
                    evidence=f_data.get("evidence"),
                    package_name=f_data.get("package_name"),
                    package_version=f_data.get("package_version"),
                    fixed_version=f_data.get("fixed_version"),
                    cve_id=f_data.get("cve_id"),
                    remediation=f_data.get("remediation"),
                    status="open",
                    risk_score=f_data.get("risk_score", 0.0),
                    correlation_group_id=f_data.get("correlation_group_id"),
                    correlation_reason=f_data.get("correlation_reason"),
                    raw_payload=f_data.get("raw_payload"),
                )
                db.add(finding_obj)

            # Update scan stats
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.critical_count = crit_count
            scan.high_count = high_count
            scan.medium_count = med_count
            scan.low_count = low_count
            scan.gate_status = gate_res.status
            scan.gate_reason = "; ".join(gate_res.reasons)
            scan.scanner_details = scanner_info

            await db.commit()
            await db.refresh(scan)
            return scan

        except Exception as e:
            logger.error("Scan pipeline execution failed", scan_id=scan_id, error=str(e))
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            scan.gate_status = "failed"
            scan.gate_reason = f"Scan aborted due to runtime error: {str(e)}"
            await db.commit()
            await db.refresh(scan)
            return scan
