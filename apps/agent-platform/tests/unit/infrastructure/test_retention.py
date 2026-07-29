from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_platform.infrastructure.retention import (
    RetentionCandidate,
    RetentionService,
)


@pytest.mark.asyncio
async def test_retention_deletes_expired_content_but_archives_audit_chain() -> None:
    now = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)
    deleted: list[str] = []
    archived: list[str] = []

    async def delete(candidate: RetentionCandidate) -> None:
        deleted.append(candidate.resource_id)

    async def archive(candidate: RetentionCandidate) -> None:
        archived.append(candidate.resource_id)

    service = RetentionService(delete=delete, archive=archive)
    report = await service.sweep(
        [
            RetentionCandidate(
                tenant_id="tenant-a",
                resource_type="artifact",
                resource_id="artifact-expired",
                expires_at=now - timedelta(seconds=1),
            ),
            RetentionCandidate(
                tenant_id="tenant-a",
                resource_type="run_event",
                resource_id="event-expired",
                expires_at=now - timedelta(seconds=1),
                immutable_audit=True,
            ),
            RetentionCandidate(
                tenant_id="tenant-a",
                resource_type="artifact",
                resource_id="artifact-active",
                expires_at=now + timedelta(days=1),
            ),
        ],
        now=now,
    )

    assert report.scanned == 3
    assert report.deleted == 1
    assert report.archived == 1
    assert report.retained == 1
    assert deleted == ["artifact-expired"]
    assert archived == ["event-expired"]
