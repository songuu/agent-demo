from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.agents.openai_runtime import (
    ModelPrice,
    ModelPriceCatalog,
    RuntimeBudgetHooks,
)
from agent_platform.application.dag_scheduler import BudgetLedger
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
from agent_platform.tools.function_tools import AgentToolContext


def _contract() -> TaskContract:
    return TaskContract(
        goal="Return one bounded answer",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Answer exists",
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


@pytest.mark.asyncio
async def test_every_sdk_model_turn_preflights_and_third_identical_turn_pauses() -> None:
    store = InMemoryPlatformStore()
    contract = _contract()
    run_id = uuid4()
    run, _ = await store.runs.create_once(
        RunRecord(
            run_id=run_id,
            tenant_id=contract.principal.tenant_id,
            principal_id=contract.principal.user_id,
            contract=contract,
            idempotency_key="model-turns",
            request_hash="request-hash",
            workflow_id=f"run-{run_id}",
            status=RunStatus.PLANNING,
        )
    )
    guard = TrajectoryGuard(store.runs)
    hooks = RuntimeBudgetHooks(
        budget=BudgetLedger.for_runtime(
            max_cost_usd=contract.max_cost_usd,
            max_tool_calls=contract.max_tool_calls,
            remaining_seconds=contract.max_duration_seconds,
        ),
        pricing=ModelPriceCatalog(
            catalog_version="test-1",
            models={
                "gpt-5.6-sol": ModelPrice(
                    input_usd_per_million_tokens=Decimal("1"),
                    output_usd_per_million_tokens=Decimal("1"),
                )
            },
        ),
        trajectory_guard=guard,
    )
    wrapper = SimpleNamespace(
        context=AgentToolContext(
            run_id=run.run_id,
            task_id="planner",
            plan_version=0,
            principal=contract.principal,
            data_scope=contract.data_scope,
            allowed_capabilities=frozenset(),
            correlation_id="corr-model",
            gateway=object(),
        )
    )
    agent = SimpleNamespace(model="gpt-5.6-sol", name="planner")
    response = SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=1,
            output_tokens=1,
            input_tokens_details=SimpleNamespace(cached_tokens=0),
        )
    )
    input_items = [{"role": "user", "content": "bounded input"}]

    for _ in range(2):
        await hooks.on_llm_start(wrapper, agent, None, input_items)
        await hooks.on_llm_end(wrapper, agent, response)

    with pytest.raises(PlatformError, match="TRAJECTORY_PAUSED"):
        await hooks.on_llm_start(wrapper, agent, None, input_items)

    persisted = await store.runs.get(run.run_id, run.tenant_id)
    assert persisted.status is RunStatus.PAUSED
    events = await store.runs.events_after(run.run_id, run.tenant_id, 0)
    assert sum(event.event_type == "trajectory.candidate" for event in events) == 3
    assert events[-1].event_type == "trajectory.decision"
    assert "REPEATED_OPERATION_LOOP" in events[-1].payload["reason_codes"]