"""Expand-only model for auditable short-lived Artifact downloads."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from agent_platform.infrastructure.persistence.models import Base


class ArtifactDownloadAudit(Base):
    __tablename__ = "artifact_download_audit"
    __table_args__ = (
        Index(
            "idx_artifact_download_audit_artifact",
            "tenant_id",
            "artifact_id",
            "created_at",
        ),
    )

    download_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    artifact_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("artifacts.artifact_id", ondelete="RESTRICT"),
    )
    tenant_id: Mapped[str] = mapped_column(Text)
    principal_id: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
