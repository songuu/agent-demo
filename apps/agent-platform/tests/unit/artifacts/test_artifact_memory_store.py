from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from agent_platform.application.errors import NotFound
from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.memory_store import InMemoryArtifactStore


def artifact(*, tenant_id: str = "tenant-a") -> ArtifactRecord:
    content = b"source-backed artifact"
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id=tenant_id,
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by="user-a",
    )


@pytest.mark.asyncio
async def test_get_hides_expired_and_cross_tenant_artifacts() -> None:
    store = InMemoryArtifactStore()
    active = artifact()
    expired = replace(
        active,
        artifact_id=uuid4(),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    await store.put(active)
    await store.put(expired)

    with pytest.raises(NotFound):
        await store.get(active.artifact_id, "tenant-b")
    with pytest.raises(NotFound):
        await store.get(expired.artifact_id, "tenant-a")


@pytest.mark.asyncio
async def test_delete_is_idempotent_for_owner_without_exposing_other_tenants() -> None:
    store = InMemoryArtifactStore()
    owned = artifact()
    foreign = artifact(tenant_id="tenant-b")
    await store.put(owned)
    await store.put(foreign)

    await store.delete(owned.artifact_id, "tenant-a")
    await store.delete(owned.artifact_id, "tenant-a")
    await store.delete(uuid4(), "tenant-a")
    with pytest.raises(NotFound):
        await store.delete(foreign.artifact_id, "tenant-a")

    with pytest.raises(NotFound):
        await store.get(owned.artifact_id, "tenant-a")
