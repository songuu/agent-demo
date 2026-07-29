from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.application.errors import Conflict, NotFound
from agent_platform.application.records import ActionRecord, RunRecord
from agent_platform.domain.enums import RiskLevel
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore


def make_run(*, tenant_id: str = "tenant-a", idempotency_key: str = "request-1") -> RunRecord:
    run_id = uuid4()
    return RunRecord(
        run_id=run_id,
        tenant_id=tenant_id,
        principal_id="user-1",
        contract=SimpleNamespace(max_cost_usd=Decimal("5")),
        idempotency_key=idempotency_key,
        request_hash="request-hash",
        workflow_id=f"run-{run_id}",
    )


@pytest.mark.asyncio
async def test_run_idempotency_and_tenant_non_disclosure() -> None:
    store = InMemoryPlatformStore()
    run = make_run()
    stored, created = await store.runs.create_once(run)
    duplicate, duplicate_created = await store.runs.create_once(
        make_run(idempotency_key=run.idempotency_key)
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate.run_id == stored.run_id

    with pytest.raises(NotFound):
        await store.runs.get(stored.run_id, "tenant-b")


@pytest.mark.asyncio
async def test_same_idempotency_key_with_different_request_is_conflict() -> None:
    store = InMemoryPlatformStore()
    run = make_run()
    await store.runs.create_once(run)
    changed = make_run(idempotency_key=run.idempotency_key)
    changed.request_hash = "different"

    with pytest.raises(Conflict, match="different request"):
        await store.runs.create_once(changed)


@pytest.mark.asyncio
async def test_optimistic_version_and_event_sequence_are_enforced() -> None:
    store = InMemoryPlatformStore()
    run, _ = await store.runs.create_once(make_run())
    event1 = await store.runs.append_event(run, "run.status_changed", {}, "corr-1")
    event2 = await store.runs.append_event(run, "plan.created", {}, "corr-1")

    assert (event1.sequence_no, event2.sequence_no) == (1, 2)
    expected = run.version
    run.progress = 0.5
    saved = await store.runs.save(run, expected_version=expected)
    assert saved.version == expected + 1

    with pytest.raises(Conflict, match="version"):
        await store.runs.save(saved, expected_version=expected)


@pytest.mark.asyncio
async def test_action_lock_and_business_idempotency_suppress_duplicates() -> None:
    store = InMemoryPlatformStore()
    run, _ = await store.runs.create_once(make_run())
    action = ActionRecord(
        action_id=uuid4(),
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        principal_id=run.principal_id,
        action_type="email.send",
        tool_name="email.prepare",
        tool_version="1.0.0",
        canonical_payload={"subject": "A"},
        payload_hash="a" * 64,
        preview={"subject": "A"},
        risk=RiskLevel.HIGH,
        approval_policy="human",
        required_approvals=1,
        idempotency_key="business-1",
        policy_version="builtin-1",
        expires_at=datetime.now(UTC).replace(year=2099),
    )
    stored, created = await store.actions.create_once(action)
    copy = (
        ActionRecord(**{**action.__dict__, "action_id": uuid4()})
        if hasattr(action, "__dict__")
        else action
    )
    duplicate, duplicate_created = await store.actions.create_once(copy)

    assert created is True
    assert duplicate_created is False
    assert duplicate.action_id == stored.action_id

    async with store.actions.get_for_update(stored.action_id, stored.tenant_id) as locked:
        locked.preview["locked"] = True

    assert (await store.actions.get(stored.action_id, stored.tenant_id)).preview["locked"] is True
