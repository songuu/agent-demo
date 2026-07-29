from __future__ import annotations

from decimal import Decimal
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import RunRecord
from agent_platform.application.trajectory_monitor import TrajectoryGuard
from agent_platform.domain.enums import RiskLevel, RunStatus
from agent_platform.domain.models import (
    DataScope,
    Principal,
    SuccessCriterion,
    TaskContract,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.workflows.activities import ActivityDependencies, TemporalActivities


def _contract() -> TaskContract:
    return TaskContract(
        goal="Run one bounded worker activity",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Worker returns",
                verification="schema",
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            scopes={"knowledge:read"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge"},
        ),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities={"knowledge.search"},
        max_cost_usd=Decimal("5"),
        max_duration_seconds=120,
        max_tool_calls=5,
    )


def _activities(store: InMemoryPlatformStore) -> TemporalActivities:
    return TemporalActivities(
        ActivityDependencies(
            store=store,
            runtime=object(),
            gateway=object(),
            run_service=object(),
            commit_service=object(),
            trajectory_guard=TrajectoryGuard(store.runs),
        )
    )


@pytest.mark.asyncio
async def test_trajectory_replays_across_activity_instances_and_blocks_next_runtime_step() -> None:
    store = InMemoryPlatformStore()
    contract = _contract()
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id=contract.principal.tenant_id,
            principal_id=contract.principal.user_id,
            contract=contract,
            idempotency_key="activity-replay",
            request_hash="request-hash",
            workflow_id=f"run-{run_id}",
            status=RunStatus.EXECUTING,
            current_plan_version=1,
        )
    )
    calls = 0

    async def operation(context: object) -> str:
        nonlocal calls
        del context
        calls += 1
        return "ok"

    payload = {
        "run_id": str(run.run_id),
        "tenant_id": run.tenant_id,
        "correlation_id": "corr-activity",
    }
    assert (
        await _activities(store)._invoke_runtime(
            payload,
            run,
            operation,
            role="worker",
            task_id="task-1",
        )
        == "ok"
    )
    recovered = await store.runs.get(run.run_id, run.tenant_id)
    assert (
        await _activities(store)._invoke_runtime(
            payload,
            recovered,
            operation,
            role="worker",
            task_id="task-1",
        )
        == "ok"
    )
    recovered_again = await store.runs.get(run.run_id, run.tenant_id)
    with pytest.raises(PlatformError, match="TRAJECTORY_PAUSED"):
        await _activities(store)._invoke_runtime(
            payload,
            recovered_again,
            operation,
            role="worker",
            task_id="task-1",
        )

    assert calls == 2
    assert (await store.runs.get(run.run_id, run.tenant_id)).status is RunStatus.PAUSED
