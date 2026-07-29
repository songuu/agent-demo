from __future__ import annotations

import pytest

from agent_platform.application.records import CapabilityRecord
from agent_platform.infrastructure.memory_store import InMemoryCapabilityStore


@pytest.mark.asyncio
async def test_tenant_capability_override_shadows_global_and_order_is_stable() -> None:
    store = InMemoryCapabilityStore()
    await store.register(
        "*",
        CapabilityRecord(
            name="knowledge.search",
            version="1.0.0",
            effect="read",
            risk="low",
        ),
    )
    await store.register(
        "*",
        CapabilityRecord(
            name="email.prepare",
            version="1.0.0",
            effect="prepare",
            risk="high",
        ),
    )
    disabled = await store.set_enabled(
        "tenant-a",
        "email.prepare",
        False,
        "incident response",
    )

    records = await store.list("tenant-a")

    assert disabled.enabled is False
    assert [record.name for record in records] == [
        "email.prepare",
        "knowledge.search",
    ]
    assert len([record for record in records if record.name == "email.prepare"]) == 1
    assert records[0].enabled is False
