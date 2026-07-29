from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.agents.context_builder import ContextBuilder
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_router import ModelPolicy
from agent_platform.agents.openai_runtime import (
    ModelPrice,
    ModelPriceCatalog,
    OpenAIAgentRuntime,
    OpenAIRuntimeContext,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.domain.enums import RiskLevel
from agent_platform.domain.models import (
    DataScope,
    ExecutionPlan,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
)
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.tools.function_tools import AgentToolContext


class _UsageRunner:
    def __init__(self, output: object, *, fail: bool = False) -> None:
        self._output = output
        self._fail = fail

    async def run(
        self,
        agent: object,
        model_input: str,
        *,
        context: object,
        max_turns: int,
    ) -> object:
        del agent, model_input, context, max_turns
        if self._fail:
            raise RuntimeError("MODEL_UNAVAILABLE")
        return SimpleNamespace(
            final_output=self._output,
            raw_responses=[
                SimpleNamespace(
                    usage=SimpleNamespace(
                        input_tokens=17,
                        output_tokens=5,
                    )
                )
            ],
        )


def _pricing() -> ModelPriceCatalog:
    price = ModelPrice(
        input_usd_per_million_tokens=Decimal("1"),
        output_usd_per_million_tokens=Decimal("1"),
    )
    return ModelPriceCatalog(
        catalog_version="test",
        models={
            "gpt-5.6-sol": price,
            "gpt-5.6-terra": price,
            "gpt-5.6-luna": price,
        },
    )


def _contract() -> TaskContract:
    return TaskContract(
        goal="Evidence-backed answer",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Has evidence",
                verification="evidence",
                evidence_required=True,
            )
        ],
        principal=Principal(
            user_id="user",
            tenant_id="tenant",
            scopes={"knowledge:read"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant",
            resource_types={"knowledge"},
        ),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities={"knowledge.search"},
        max_cost_usd=Decimal("2"),
        max_duration_seconds=120,
    )


def _plan() -> ExecutionPlan:
    task = TaskSpec(
        id="final",
        kind="analysis",
        objective="Answer",
        capability_names=["knowledge.search"],
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.5"),
    )
    return ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id="final",
        expected_total_cost_usd=Decimal("0.5"),
    )


def _prompts(tmp_path: Path) -> PromptRegistry:
    records: list[dict[str, str]] = []
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
    return PromptRegistry(tmp_path)


def _context(contract: TaskContract) -> OpenAIRuntimeContext:
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
        budget=BudgetLedger.for_runtime(
            max_cost_usd=contract.max_cost_usd,
            max_tool_calls=contract.max_tool_calls,
            remaining_seconds=contract.max_duration_seconds,
        ),
    )


def _factory(tmp_path: Path) -> AgentFactory:
    return AgentFactory(
        model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
        prompts=_prompts(tmp_path),
    )


@pytest.mark.asyncio
async def test_openai_runtime_records_request_status_and_sdk_usage_tokens(
    tmp_path: Path,
) -> None:
    registry = CollectorRegistry()
    observability = RuntimeObservability(PlatformMetrics(registry), environment="test")
    contract = _contract()
    runtime = OpenAIAgentRuntime(
        factory=_factory(tmp_path),
        runner=_UsageRunner(_plan()),
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=_pricing(),
        observability=observability,
    )

    await runtime.plan(_context(contract), contract)

    output = generate_latest(registry).decode()
    assert (
        'agent_model_requests_total{environment="test",model="gpt-5.6-sol",'
        'role="planner",status="success"} 1.0'
    ) in output
    assert (
        'agent_model_tokens_total{direction="input",environment="test",'
        'model="gpt-5.6-sol",role="planner"} 17.0'
    ) in output
    assert (
        'agent_model_tokens_total{direction="output",environment="test",'
        'model="gpt-5.6-sol",role="planner"} 5.0'
    ) in output


@pytest.mark.asyncio
async def test_openai_runtime_records_failed_request_without_model_content(
    tmp_path: Path,
) -> None:
    registry = CollectorRegistry()
    observability = RuntimeObservability(PlatformMetrics(registry), environment="test")
    contract = _contract()
    runtime = OpenAIAgentRuntime(
        factory=_factory(tmp_path),
        runner=_UsageRunner(_plan(), fail=True),
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=_pricing(),
        observability=observability,
    )

    with pytest.raises(RuntimeError, match="MODEL_UNAVAILABLE"):
        await runtime.plan(_context(contract), contract)

    output = generate_latest(registry).decode()
    assert (
        'agent_model_requests_total{environment="test",model="gpt-5.6-sol",'
        'role="planner",status="error"} 1.0'
    ) in output
    assert "MODEL_UNAVAILABLE" not in output
