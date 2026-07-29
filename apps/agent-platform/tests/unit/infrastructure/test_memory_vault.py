from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.infrastructure.memory_vault import MemoryVault


@pytest.mark.asyncio
async def test_memory_requires_explicit_approval_and_encrypts_plaintext() -> None:
    vault = MemoryVault(encryption_key=b"k" * 32)

    with pytest.raises(PlatformError, match="MEMORY_WRITE_REQUIRES_APPROVAL"):
        await vault.write(
            tenant_id="tenant-a",
            subject_type="user",
            subject_id="user-1",
            memory_type="preference",
            content="Use concise Chinese.",
            owner_id="user-1",
            classification="internal",
            write_policy="explicit-user-approval",
            approved=False,
        )

    record = await vault.write(
        tenant_id="tenant-a",
        subject_type="user",
        subject_id="user-1",
        memory_type="preference",
        content="Use concise Chinese.",
        owner_id="user-1",
        classification="internal",
        write_policy="explicit-user-approval",
        approved=True,
    )

    assert b"Use concise Chinese." not in record.ciphertext
    views = await vault.list_visible("tenant-a", "user-1")
    assert [item.content for item in views] == ["Use concise Chinese."]


@pytest.mark.asyncio
async def test_memory_correction_supersedes_and_delete_is_audited() -> None:
    vault = MemoryVault(encryption_key=b"k" * 32)
    original = await vault.write(
        tenant_id="tenant-a",
        subject_type="project",
        subject_id="project-1",
        memory_type="decision",
        content="Use model A.",
        owner_id="user-1",
        classification="internal",
        write_policy="project-owner",
        approved=True,
    )

    corrected = await vault.correct(
        original.memory_id,
        tenant_id="tenant-a",
        actor_id="user-1",
        content="Use model B.",
        reason="Architecture decision changed.",
    )
    active = await vault.list_visible("tenant-a", "user-1")
    assert [item.content for item in active] == ["Use model B."]

    await vault.delete(
        corrected.memory_id,
        tenant_id="tenant-a",
        actor_id="user-1",
        reason="User requested erasure.",
    )
    assert await vault.list_visible("tenant-a", "user-1") == ()
    lifecycle = await vault.lifecycle("tenant-a", original.memory_id)
    assert [event.event_type for event in lifecycle] == ["created", "superseded"]
    corrected_lifecycle = await vault.lifecycle("tenant-a", corrected.memory_id)
    assert [event.event_type for event in corrected_lifecycle] == ["corrected", "deleted"]


@pytest.mark.asyncio
async def test_memory_tenant_boundary_and_expiration() -> None:
    vault = MemoryVault(encryption_key=b"k" * 32)
    now = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)
    record = await vault.write(
        tenant_id="tenant-a",
        subject_type="user",
        subject_id="user-1",
        memory_type="preference",
        content="Temporary preference.",
        owner_id="user-1",
        classification="internal",
        write_policy="explicit-user-approval",
        approved=True,
        valid_until=now + timedelta(minutes=1),
        now=now,
    )

    with pytest.raises(NotFound):
        await vault.get(record.memory_id, "tenant-b")
    assert await vault.list_visible(
        "tenant-a", "user-1", now=now + timedelta(minutes=2)
    ) == ()
