from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope
from agent_platform.infrastructure.memory_vault import MemoryVault


def scope(
    tenant_id: str = "tenant-a",
    *,
    resource_id: str = "doc-1",
    classification: DataClassification = DataClassification.INTERNAL,
) -> DataScope:
    return DataScope(
        tenant_id=tenant_id,
        resource_types={"knowledge"},
        resource_ids={resource_id},
        classifications={classification},
    )


async def write_memory(
    vault: MemoryVault,
    *,
    tenant_id: str = "tenant-a",
    owner_id: str = "user-1",
    purpose: str = "market-research",
    data_scope: DataScope | None = None,
    classification: str = "internal",
    now: datetime,
    valid_until: datetime | None = None,
) -> None:
    await vault.write(
        tenant_id=tenant_id,
        subject_type="user",
        subject_id=owner_id,
        memory_type="preference",
        content=(
            f"{tenant_id}/{owner_id}/{purpose}/"
            f"{data_scope.resource_ids if data_scope else 'default'}/{classification}"
        ),
        owner_id=owner_id,
        classification=classification,
        write_policy="explicit-user-approval",
        approved=True,
        purpose=purpose,
        data_scope=data_scope or scope(tenant_id),
        valid_until=valid_until,
        now=now,
    )


@pytest.mark.asyncio
async def test_context_query_strictly_filters_all_authorization_dimensions() -> None:
    vault = MemoryVault(encryption_key=b"k" * 32)
    now = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)
    await write_memory(vault, now=now)
    await write_memory(vault, tenant_id="tenant-b", data_scope=scope("tenant-b"), now=now)
    await write_memory(vault, owner_id="user-2", now=now)
    await write_memory(vault, purpose="incident-review", now=now)
    await write_memory(vault, data_scope=scope(resource_id="doc-2"), now=now)
    await write_memory(
        vault,
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge"},
            classifications={"internal"},
        ),
        now=now,
    )
    await write_memory(
        vault,
        classification="confidential",
        data_scope=scope(classification=DataClassification.CONFIDENTIAL),
        now=now,
    )
    await write_memory(
        vault,
        valid_until=now + timedelta(seconds=1),
        now=now,
    )
    await write_memory(vault, now=now + timedelta(days=1))

    visible = await vault.list_for_context(
        tenant_id="tenant-a",
        principal_id="user-1",
        data_scope=scope(),
        purpose="market-research",
        now=now + timedelta(seconds=2),
    )

    assert len(visible) == 1
    assert visible[0].owner_id == "user-1"
    assert visible[0].purpose == "market-research"
    assert visible[0].data_scope == scope()

    with pytest.raises(PlatformError, match="MEMORY_QUERY_SCOPE_TENANT_MISMATCH"):
        await vault.list_for_context(
            tenant_id="tenant-a",
            principal_id="user-1",
            data_scope=scope("tenant-b"),
            purpose="market-research",
        )


@pytest.mark.asyncio
async def test_correction_and_delete_preserve_true_actor_and_provenance() -> None:
    vault = MemoryVault(encryption_key=b"k" * 32)
    original = await vault.write(
        tenant_id="tenant-a",
        subject_type="project",
        subject_id="project-1",
        memory_type="decision",
        content="Use model A.",
        owner_id="owner-1",
        classification="internal",
        write_policy="project-owner",
        approved=True,
        purpose="architecture",
        data_scope=scope(resource_id="project-1"),
    )

    corrected = await vault.correct(
        original.memory_id,
        tenant_id="tenant-a",
        actor_id="admin-2",
        content="Use model B.",
        reason="Approved architecture correction.",
    )
    assert corrected.owner_id == "owner-1"
    assert corrected.version == 2
    original_events = await vault.lifecycle("tenant-a", original.memory_id)
    corrected_events = await vault.lifecycle("tenant-a", corrected.memory_id)
    assert original_events[-1].actor_id == "admin-2"
    assert original_events[-1].previous_hash == original.content_hash
    assert corrected_events[0].event_type == "corrected"
    assert corrected_events[0].actor_id == "admin-2"
    assert corrected_events[0].previous_hash == original.content_hash

    await vault.delete(
        corrected.memory_id,
        tenant_id="tenant-a",
        actor_id="privacy-officer-3",
        reason="Approved erasure.",
    )
    corrected_events = await vault.lifecycle("tenant-a", corrected.memory_id)
    assert corrected_events[-1].event_type == "deleted"
    assert corrected_events[-1].actor_id == "privacy-officer-3"
    assert corrected_events[-1].previous_hash == corrected.content_hash
