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
from agent_platform.agents.deterministic_runtime import RuntimeExecutionContext
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_router import ModelPolicy
from agent_platform.agents.openai_runtime import (
    ModelPrice,
    ModelPriceCatalog,
    OpenAIAgentRuntime,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.domain.enums import RiskLevel, TrustLevel
from agent_platform.domain.models import (
    Claim,
    CriterionVerification,
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


@pytest.mark.asyncio
async def test_openai_runtime_accepts_workflow_activity_context(
    tmp_path: Path,
) -> None:
    contract = TaskContract(
        goal="Return an evidence-backed answer.",
        success_criteria=[
            SuccessCriterion(
                id="sc-1",
                description="Has evidence.",
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
    task = TaskSpec(
        id="final",
        kind="analysis",
        objective="Answer.",
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
        supports_criterion_ids=["sc-1"],
        trust=TrustLevel.TRUSTED,
    )
    worker_output = WorkerOutput(
        summary="Evidence-backed answer.",
        claims=[
            Claim(
                claim_id="claim-1",
                statement="Supported statement.",
                confidence=0.9,
                evidence_ids=[evidence.evidence_id],
            )
        ],
        evidence=[evidence],
        criterion_verifications=[
            CriterionVerification(
                criterion_id="sc-1",
                method="evidence",
                passed=True,
                checked_at=datetime.now(UTC),
                evidence_ids=[evidence.evidence_id],
                verifier_version="test@1",
            )
        ],
    )
    runner = _Runner([plan, worker_output, VerificationReport(verdict="pass")])
    prompts = _prompt_registry(tmp_path)
    runtime = OpenAIAgentRuntime(
        factory=AgentFactory(
            model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
            prompts=prompts,
        ),
        runner=runner,
        context_builder=ContextBuilder(),
        known_capabilities=frozenset({"knowledge.search"}),
        pricing=_pricing(),
    )
    workflow_context = RuntimeExecutionContext(
        run_id=uuid4(),
        contract=contract,
        correlation_id="activity-correlation",
        gateway=object(),
        artifact_store=object(),
        budget=BudgetLedger.for_runtime(
            max_cost_usd=contract.max_cost_usd,
            max_tool_calls=contract.max_tool_calls,
            remaining_seconds=contract.max_duration_seconds,
        ),
    )

    result = await runtime.plan(workflow_context, contract)
    executed = await runtime.execute_task(workflow_context, task, {})
    verified = await runtime.verify(
        workflow_context,
        contract,
        plan,
        {"final": worker_output},
    )

    assert result == plan
    assert executed == worker_output
    assert verified.verdict == "pass"
    assert [context.task_id for context in runner.contexts] == [
        "planner",
        "final",
        "verifier",
    ]
    assert [context.plan_version for context in runner.contexts] == [0, 1, 1]
    assert runner.contexts[0].allowed_capabilities == frozenset()
    assert runner.contexts[1].allowed_capabilities == frozenset({"knowledge.search"})
    assert runner.contexts[2].allowed_capabilities == frozenset()
    assert all(context.principal is contract.principal for context in runner.contexts)
    assert all(context.data_scope is contract.data_scope for context in runner.contexts)
    assert all(context.gateway is workflow_context.gateway for context in runner.contexts)
    assert all(context.correlation_id == "activity-correlation" for context in runner.contexts)


class _Runner:
    def __init__(self, outputs: list[object]) -> None:
        self._outputs = list(outputs)
        self.contexts: list[object] = []

    async def run(
        self,
        agent: object,
        model_input: str,
        *,
        context: object,
        max_turns: int,
    ) -> object:
        del agent, model_input, max_turns
        assert context.__class__.__name__ == "AgentToolContext"
        self.contexts.append(context)
        return SimpleNamespace(final_output=self._outputs.pop(0))


def _prompt_registry(tmp_path: Path) -> PromptRegistry:
    records = []
    for role in ("planner", "worker", "verifier"):
        path = tmp_path / f"{role}.md"
        path.write_text(f"{role} bounded instructions", encoding="utf-8")
        records.append(
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
        json.dumps({"schema_version": "1.0", "prompts": records}),
        encoding="utf-8",
    )
    return PromptRegistry(tmp_path)
