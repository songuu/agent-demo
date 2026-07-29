from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.agents.context_builder import ContextBuilder
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_router import ModelPolicy
from agent_platform.agents.openai_runtime import (
    ModelPrice,
    ModelPriceCatalog,
    ModelUsage,
    OpenAIAgentRuntime,
    OpenAIRuntimeContext,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import RiskLevel
from agent_platform.domain.models import (
    DataScope,
    ExecutionPlan,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    WorkerOutput,
)
from agent_platform.tools.function_tools import AgentToolContext


def _contract(*, max_cost_usd: str = "1", max_tool_calls: int = 1) -> TaskContract:
    return TaskContract(
        goal="Return a bounded result.",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="A result exists.",
                verification="schema",
            )
        ],
        principal=Principal(
            user_id="user",
            tenant_id="tenant",
            scopes={"knowledge:read"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(tenant_id="tenant", resource_types={"knowledge"}),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities={"knowledge.search"},
        max_cost_usd=Decimal(max_cost_usd),
        max_duration_seconds=120,
        max_tool_calls=max_tool_calls,
    )


def _factory(tmp_path: Path) -> AgentFactory:
    records = []
    for role in ("planner", "worker", "verifier"):
        prompt = tmp_path / f"{role}.md"
        prompt.write_text(f"{role} bounded instructions", encoding="utf-8")
        records.append(
            {
                "prompt_id": role,
                "version": "1.0.0",
                "role": role,
                "path": prompt.name,
                "sha256": hashlib.sha256(prompt.read_bytes()).hexdigest(),
                "git_sha": "test",
                "status": "approved",
            }
        )
    (tmp_path / "registry.json").write_text(
        json.dumps({"schema_version": "1.0", "prompts": records}),
        encoding="utf-8",
    )
    return AgentFactory(
        model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
        prompts=PromptRegistry(tmp_path),
    )


def _pricing() -> ModelPriceCatalog:
    return ModelPriceCatalog(
        catalog_version="test-2026-07-24",
        models={
            name: ModelPrice(
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("1"),
            )
            for name in ("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")
        },
    )


def _context(contract: TaskContract, ledger: BudgetLedger) -> OpenAIRuntimeContext:
    return OpenAIRuntimeContext(
        agent_context=AgentToolContext(
            run_id=uuid4(),
            task_id="planner",
            plan_version=0,
            principal=contract.principal,
            data_scope=contract.data_scope,
            allowed_capabilities=contract.allowed_capabilities,
            correlation_id="corr-1",
            gateway=object(),
        ),
        contract=contract,
        budget=ledger,
    )


class _TwoTurnRunner:
    def __init__(self, plan: ExecutionPlan) -> None:
        self._plan = plan
        self.model_requests = 0

    async def run(
        self,
        agent: object,
        model_input: str,
        *,
        context: object,
        max_turns: int,
        hooks: object,
    ) -> object:
        del model_input, max_turns
        await hooks.on_llm_start(context, agent, None, [])
        self.model_requests += 1
        await hooks.on_llm_end(
            context,
            agent,
            SimpleNamespace(
                usage=SimpleNamespace(
                    input_tokens=1_000_000,
                    output_tokens=0,
                    input_tokens_details=SimpleNamespace(cached_tokens=0),
                )
            ),
        )
        await hooks.on_llm_start(context, agent, None, [])
        self.model_requests += 1
        return SimpleNamespace(final_output=self._plan)


@pytest.mark.asyncio
async def test_fake_model_stops_before_next_request_after_actual_cost_reaches_100_percent(
    tmp_path: Path,
) -> None:
    contract = _contract()
    task = TaskSpec(
        id="final",
        kind="analysis",
        objective="Answer.",
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        estimated_cost_usd=Decimal("0.1"),
    )
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id=task.id,
        expected_total_cost_usd=task.estimated_cost_usd,
    )
    runner = _TwoTurnRunner(plan)
    ledger = BudgetLedger.for_runtime(
        max_cost_usd=contract.max_cost_usd,
        max_tool_calls=contract.max_tool_calls,
        remaining_seconds=contract.max_duration_seconds,
    )
    runtime = OpenAIAgentRuntime(
        factory=_factory(tmp_path),
        runner=runner,
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=_pricing(),
    )

    with pytest.raises(PlatformError, match="BUDGET_EXHAUSTED"):
        await runtime.plan(_context(contract, ledger), contract)

    assert runner.model_requests == 1
    assert ledger.cost_usd == Decimal("1")
    assert ledger.usage.input_tokens == 1_000_000
    assert ledger.usage.cost_usd == Decimal("1")
    assert ledger.usage.pricing_catalog_version == "test-2026-07-24"


class _TwoToolRunner:
    def __init__(self) -> None:
        self.tool_invocations = 0

    async def run(
        self,
        agent: object,
        model_input: str,
        *,
        context: object,
        max_turns: int,
        hooks: object,
    ) -> object:
        del model_input, max_turns
        await hooks.on_llm_start(context, agent, None, [])
        await hooks.on_llm_end(
            context,
            agent,
            SimpleNamespace(
                usage=SimpleNamespace(
                    input_tokens=1,
                    output_tokens=1,
                    input_tokens_details=SimpleNamespace(cached_tokens=0),
                )
            ),
        )
        tool = SimpleNamespace(name="knowledge.search")
        await hooks.on_tool_start(context, agent, tool)
        self.tool_invocations += 1
        await hooks.on_tool_start(context, agent, tool)
        self.tool_invocations += 1
        return SimpleNamespace(final_output=WorkerOutput(summary="should not be returned"))


@pytest.mark.asyncio
async def test_fake_tool_stops_before_call_beyond_actual_tool_budget(
    tmp_path: Path,
) -> None:
    contract = _contract(max_cost_usd="10", max_tool_calls=1)
    task = TaskSpec(
        id="research",
        kind="research",
        objective="Search once.",
        capability_names=["knowledge.search"],
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        max_tool_calls=1,
        estimated_cost_usd=Decimal("0.1"),
    )
    runner = _TwoToolRunner()
    ledger = BudgetLedger.for_runtime(
        max_cost_usd=contract.max_cost_usd,
        max_tool_calls=contract.max_tool_calls,
        remaining_seconds=contract.max_duration_seconds,
    )
    runtime = OpenAIAgentRuntime(
        factory=_factory(tmp_path),
        runner=runner,
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=_pricing(),
    )

    with pytest.raises(PlatformError, match="BUDGET_EXHAUSTED"):
        await runtime.execute_task(_context(contract, ledger), task, {})

    assert runner.tool_invocations == 1
    assert ledger.tool_calls == 1
    assert ledger.usage.tool_calls == 1


def test_model_price_catalog_loads_versioned_rates_from_data(tmp_path: Path) -> None:
    catalog_path = tmp_path / "model-pricing.json"
    catalog_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "catalog_version": "billing-2026-07",
                "currency": "USD",
                "models": {
                    "gpt-5.6-sol": {
                        "input_usd_per_million_tokens": "2",
                        "cached_input_usd_per_million_tokens": "0.5",
                        "output_usd_per_million_tokens": "4",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    catalog = ModelPriceCatalog.from_path(
        catalog_path,
        allowed_models=("gpt-5.6-sol",),
    )

    assert catalog.catalog_version == "billing-2026-07"
    assert catalog.quote(
        "gpt-5.6-sol",
        ModelUsage(
            input_tokens=1_000_000,
            cached_input_tokens=500_000,
            output_tokens=250_000,
        ),
    ) == Decimal("2.25")


def test_model_price_catalog_rejects_unknown_models_before_the_call() -> None:
    with pytest.raises(PlatformError, match="MODEL_PRICING_UNKNOWN"):
        _pricing().require_model("gpt-unknown")
