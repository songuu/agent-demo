from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
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
    OpenAIAgentRuntime,
    OpenAIRuntimeContext,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.domain.enums import RiskLevel
from agent_platform.domain.models import (
    Claim,
    DataScope,
    Evidence,
    ExecutionPlan,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
)
from agent_platform.tools.function_tools import AgentToolContext


def prompt_registry(tmp_path: Path) -> PromptRegistry:
    prompts = []
    for role in ("planner", "worker", "verifier"):
        path = tmp_path / f"{role}.md"
        path.write_text(f"{role} bounded instructions", encoding="utf-8")
        prompts.append(
            {
                "prompt_id": role,
                "version": "1.0.0",
                "role": role,
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "git_sha": "test",
                "status": "approved",
            }
        )
    (tmp_path / "registry.json").write_text(
        json.dumps({"schema_version": "1.0", "prompts": prompts}),
        encoding="utf-8",
    )
    return PromptRegistry(tmp_path)


def pricing() -> ModelPriceCatalog:
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


def budget(value: TaskContract) -> BudgetLedger:
    return BudgetLedger.for_runtime(
        max_cost_usd=value.max_cost_usd,
        max_tool_calls=value.max_tool_calls,
        remaining_seconds=value.max_duration_seconds,
    )


def contract() -> TaskContract:
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


class FakeRunner:
    def __init__(self, output: object) -> None:
        self.output = output
        self.max_turns: list[int] = []

    async def run(
        self, agent: object, model_input: str, *, context: object, max_turns: int
    ) -> object:
        self.max_turns.append(max_turns)
        assert "security_notice" in model_input
        return SimpleNamespace(final_output=self.output)


@pytest.mark.asyncio
async def test_planner_uses_structured_output_and_validates_contract(
    tmp_path: Path,
) -> None:
    value = contract()
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
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id="final",
        expected_total_cost_usd=Decimal("0.5"),
    )
    runner = FakeRunner(plan)
    factory = AgentFactory(
        model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
        prompts=prompt_registry(tmp_path),
    )
    runtime = OpenAIAgentRuntime(
        factory=factory,
        runner=runner,
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=pricing(),
    )
    agent_context = AgentToolContext(
        run_id=uuid4(),
        task_id="planner",
        plan_version=0,
        principal=value.principal,
        data_scope=value.data_scope,
        allowed_capabilities=value.allowed_capabilities,
        correlation_id="corr-1",
        gateway=object(),
    )

    result = await runtime.plan(
        OpenAIRuntimeContext(agent_context=agent_context, contract=value, budget=budget(value)),
        value,
    )

    assert result == plan
    assert runner.max_turns == [2]
    planner = factory.planner(value)
    assert planner.output_type is ExecutionPlan
    worker = factory.worker(value, task, 0)
    assert all(getattr(tool, "name", "") != "commit_action" for tool in worker.tools)


@pytest.mark.asyncio
async def test_verifier_cannot_pass_when_a_must_environment_check_failed(
    tmp_path: Path,
) -> None:
    value = contract().model_copy(
        update={
            "success_criteria": [
                SuccessCriterion(
                    id="sc-evidence",
                    description="The answer has criterion-specific evidence",
                    severity="must",
                    verification="evidence",
                    evidence_required=True,
                ),
                SuccessCriterion(
                    id="sc-environment",
                    description="The deployed endpoint is healthy",
                    severity="must",
                    verification="environment",
                ),
            ]
        }
    )
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
    plan = ExecutionPlan(
        plan_version=1,
        tasks=[task],
        final_task_id="final",
        expected_total_cost_usd=Decimal("0.5"),
    )
    evidence = Evidence(
        source_type="document",
        source_id="source-1",
        locator="page:1",
        captured_at=datetime.now(UTC),
        content_hash="a" * 64,
        supports_claim_ids=["claim-1"],
        supports_criterion_ids=["sc-evidence"],
        trust="trusted",
    )
    output = WorkerOutput.model_validate(
        {
            "summary": "One criterion is evidenced, but the environment check failed.",
            "claims": [
                Claim(
                    claim_id="claim-1",
                    statement="The documented requirement is satisfied.",
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                )
            ],
            "evidence": [evidence],
            "criterion_verifications": [
                {
                    "criterion_id": "sc-evidence",
                    "method": "evidence",
                    "passed": True,
                    "checked_at": datetime.now(UTC),
                    "evidence_ids": [evidence.evidence_id],
                },
                {
                    "criterion_id": "sc-environment",
                    "method": "environment",
                    "passed": False,
                    "checked_at": datetime.now(UTC),
                    "failure_reason": "Health endpoint returned 503.",
                },
            ],
        }
    )
    runner = FakeRunner(VerificationReport(verdict="pass"))
    factory = AgentFactory(
        model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
        prompts=prompt_registry(tmp_path),
    )
    runtime = OpenAIAgentRuntime(
        factory=factory,
        runner=runner,
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=pricing(),
    )
    agent_context = AgentToolContext(
        run_id=uuid4(),
        task_id="verifier",
        plan_version=1,
        principal=value.principal,
        data_scope=value.data_scope,
        allowed_capabilities=frozenset(),
        correlation_id="corr-verifier",
        gateway=object(),
    )

    report = await runtime.verify(
        OpenAIRuntimeContext(agent_context=agent_context, contract=value, budget=budget(value)),
        value,
        plan,
        {"final": output},
    )

    assert report.verdict == "revise"
    assert report.failed_criteria == ["sc-environment"]
    assert "sc-environment" in " ".join(report.missing_evidence)
    assert runner.max_turns == []
