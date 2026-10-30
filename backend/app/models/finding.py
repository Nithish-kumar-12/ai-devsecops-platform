"""
Finding ORM model — Unified vulnerability data model across SAST, DAST, Secrets, and SCA.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanner: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # "semgrep", "gitleaks", "osv-scanner", "zap", etc.
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # "sast", "secret", "sca", "dast", "iac"
    severity: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # "critical", "high", "medium", "low"
    confidence: Mapped[str] = mapped_column(
        String(50), default="unknown", nullable=False
    )  # "high", "medium", "low", "unknown"
    
    # Location details
    file_path: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True, index=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    column_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True, index=True)
    param: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Dependency specific (SCA)
    package_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    package_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Guidance & AI Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_fix_diff: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_verification_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Lifecycle & Risk Prioritization
    status: Mapped[str] = mapped_column(
        String(50), default="open", nullable=False, index=True
    )  # "open", "in_progress", "fixed", "retested", "closed"
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    # Correlation Engine
    correlation_group_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    correlation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Raw scanner provenance
    raw_payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    project: Mapped["Project"] = relationship("Project", back_populates="findings")
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
