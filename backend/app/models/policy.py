"""
Security Policy ORM model for CI/CD Gates and Compliance.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), default="Default Gate Policy", nullable=False)
    fail_on_critical: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    fail_on_high: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_medium: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    block_on_secrets: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    project: Mapped[Optional["Project"]] = relationship("Project")
