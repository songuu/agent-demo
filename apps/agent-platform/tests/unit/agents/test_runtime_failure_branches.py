from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.agents.context_builder import (
    ContextAssembly,
    ContextAssemblyError,
    ContextBuilder,
)
from agent_platform.agents.deterministic_runtime import (
    DeterministicAgentRuntime,
    RuntimeExecutionContext,
)
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_router import ModelPolicy
from agent_platform.agents.openai_runtime import (
    ModelPrice,
    ModelPriceCatalog,
    ModelUsage,
    OpenAIAgentRuntime,
)
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.agents.verification import deterministic_verification_findings
from agent_platform.application.errors import PlatformError
from agent_platform.domain.enums import RiskLevel
from agent_platform.domain.models import (
    CriterionVerification,
    DataScope,
    Evidence,
    Principal,
    SuccessCriterion,
    TaskContract,
    TaskSpec,
    WorkerOutput,
)
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools import function_tools


def _contract(
    *,
    criteria: list[SuccessCriterion] | None = None,
    capabilities: set[str] | None = None,
    scopes: set[str] | None = None,
    constraints: dict[str, Any] | None = None,
) -> TaskContract:
    return TaskContract(
        goal="Return one bounded, verifiable result.",
        success_criteria=criteria
        or [
            SuccessCriterion(
                id="sc-1",
                description="The result satisfies its schema.",
                verification="schema",
            )
        ],
        principal=Principal(
            user_id="user-1",
            tenant_id="tenant-a",
            scopes=scopes or {"knowledge:read"},
            auth_strength="mfa",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types={"knowledge", "artifact"},
        ),
        risk=RiskLevel.MEDIUM,
        allowed_capabilities=capabilities or set(),
        constraints=constraints or {},
        max_cost_usd=Decimal("5"),
        max_duration_seconds=120,
        max_tool_calls=5,
    )


def _task(
    *,
    task_id: str = "final",
    kind: str = "analysis",
    capabilities: list[str] | None = None,
) -> TaskSpec:
    return TaskSpec(
        id=task_id,
        kind=kind,
        objective="Return a bounded result.",
        capability_names=capabilities or [],
        output_schema="WorkerOutput@1.0",
        risk=RiskLevel.MEDIUM,
        timeout_seconds=30,
        estimated_cost_usd=Decimal("0.1"),
    )


def _runtime_context(
    contract: TaskContract,
    *,
    gateway: Any = None,
) -> RuntimeExecutionContext:
    store = InMemoryPlatformStore()
    return RuntimeExecutionContext(
        run_id=uuid4(),
        contract=contract,
        correlation_id="runtime-branches",
        gateway=gateway or object(),
        artifact_store=store.artifacts,
    )


@pytest.mark.asyncio
async def test_deterministic_runtime_covers_fail_closed_and_no_capability_paths() -> None:
    runtime = DeterministicAgentRuntime()
    contract = _contract(constraints={"markets": "not-a-list"})
    context = _runtime_context(contract)

    with pytest.raises(ValueError, match="AUDIT_RUNTIME_ROLE_UNSUPPORTED"):
        runtime.audit_metadata("verifier", contract)

    plan = await runtime.plan(context, contract)
    assert plan.tasks[0].id == "research_general"
    assert plan.tasks[0].capability_names == []
    assert (
        await runtime.execute_task(
            context,
            _task(task_id="custom"),
            {},
        )
    ).uncertainties == ["No registered capability was needed."]

    research = await runtime.execute_task(
        context,
        _task(
            task_id="research_general",
            kind="research",
        ),
        {},
    )
    assert "No authorized source capability" in research.summary

    missing = await runtime.verify(context, contract, plan, {})
    assert missing.verdict == "revise"
    assert missing.failed_criteria == ["sc-1"]

    invalid = await runtime.verify(
        context,
        contract,
        plan,
        {plan.final_task_id: WorkerOutput(summary="missing criterion check")},
    )
    assert invalid.verdict == "revise"
    assert invalid.failed_criteria == ["sc-1"]


@pytest.mark.asyncio
async def test_deterministic_research_handles_empty_provider_results() -> None:
    class _Gateway:
        async def call_read(self, *_: Any, **__: Any) -> Any:
            return SimpleNamespace(data={"items": []})

    contract = _contract(capabilities={"knowledge.search"})
    context = _runtime_context(contract, gateway=_Gateway())
    output = await DeterministicAgentRuntime().execute_task(
        context,
        _task(
            task_id="research_sg",
            kind="research",
            capabilities=["knowledge.search"],
        ),
        {},
    )

    assert output.summary == "No source matched SG"
    assert output.uncertainties == ["No authorized evidence was found for SG."]


def test_deterministic_criterion_verification_covers_all_methods() -> None:
    criteria = [
        SuccessCriterion(
            id="schema",
            description="Schema is valid.",
            verification="schema",
        ),
        SuccessCriterion(
            id="evidence",
            description="Evidence is accessible.",
            verification="evidence",
            evidence_required=True,
        ),
        SuccessCriterion(
            id="human",
            description="A human reviewed it.",
            verification="human",
        ),
    ]
    evidence = Evidence(
        source_type="document",
        source_id="source-1",
        locator="page:1",
        captured_at=datetime.now(UTC),
        content_hash="a" * 64,
        supports_criterion_ids=["evidence"],
        trust="trusted",
    )

    results = DeterministicAgentRuntime._criterion_verifications(
        _contract(criteria=criteria),
        [evidence],
    )

    assert [(item.criterion_id, item.passed) for item in results] == [
        ("schema", True),
        ("evidence", True),
        ("human", False),
    ]
    assert results[-1].failure_reason == "human verification was not performed."


def _factory() -> AgentFactory:
    return AgentFactory(
        model_policy=ModelPolicy(("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")),
        prompts=PromptRegistry(Path("prompts")),
    )


def test_agent_factory_audit_metadata_and_verifier_are_version_bound() -> None:
    factory = _factory()
    contract = _contract()
    task = _task()

    planner = factory.audit_metadata("planner", contract, retry_count=1)
    worker = factory.audit_metadata("worker", contract, task=task, retry_count=2)
    verifier = factory.verifier(contract, {"hard_failures": []})

    assert planner["prompt_id"] == "planner"
    assert worker["prompt_id"] == "worker"
    assert planner["model_settings"]["store"] is False
    assert worker["model_settings"]["include_usage"] is True
    assert verifier.output_type is not None
    with pytest.raises(ValueError, match="AUDIT_RUNTIME_ROLE_UNSUPPORTED"):
        factory.audit_metadata("verifier", contract)


def test_agent_factory_rejects_any_agent_visible_commit_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        function_tools.AGENT_FUNCTION_TOOLS,
        "malicious.write",
        SimpleNamespace(name="commit_action"),
    )

    with pytest.raises(ValueError, match="COMMIT_TOOL_NOT_AGENT_VISIBLE"):
        _factory().worker(
            _contract(),
            _task(capabilities=["malicious.write"]),
            retry_count=0,
        )


def _write_registry(
    root: Path,
    *,
    schema_version: str = "1.0",
    status: str = "approved",
    path: str = "planner.md",
) -> None:
    prompt_path = root / "planner.md"
    prompt_path.write_text("bounded planner", encoding="utf-8")
    (root / "registry.json").write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "prompts": [
                    {
                        "prompt_id": "planner",
                        "version": "1.0.0",
                        "path": path,
                        "sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
                        "git_sha": "abc123",
                        "status": status,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_prompt_registry_rejects_schema_state_lookup_and_path_escape(
    tmp_path: Path,
) -> None:
    _write_registry(tmp_path, schema_version="2.0")
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_SCHEMA_UNSUPPORTED"):
        PromptRegistry(tmp_path)

    _write_registry(tmp_path)
    registry = PromptRegistry(tmp_path)
    with pytest.raises(ValueError, match="PROMPT_NOT_FOUND"):
        registry.render("worker", "1.0.0", {})

    _write_registry(tmp_path, status="draft")
    draft = PromptRegistry(tmp_path)
    with pytest.raises(ValueError, match="PROMPT_NOT_APPROVED"):
        draft.render("planner", "1.0.0", {})
    assert draft.version_manifest() == {}

    _write_registry(tmp_path, path="../outside.md")
    with pytest.raises(ValueError, match="PROMPT_PATH_TRAVERSAL"):
        PromptRegistry(tmp_path).render("planner", "1.0.0", {})


def test_model_pricing_rejects_negative_empty_malformed_and_unknown_data(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="MODEL_PRICING_RATE_NEGATIVE"):
        ModelPrice(
            input_usd_per_million_tokens=Decimal("-1"),
            output_usd_per_million_tokens=Decimal("1"),
        )
    with pytest.raises(ValueError, match="MODEL_PRICING_CATALOG_INVALID"):
        ModelPriceCatalog(catalog_version=" ", models={})
    with pytest.raises(PlatformError, match="MODEL_PRICING_CATALOG_REQUIRED"):
        ModelPriceCatalog.from_path("", allowed_models=())

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(PlatformError, match="MODEL_PRICING_CATALOG_INVALID"):
        ModelPriceCatalog.from_path(malformed, allowed_models=())

    wrong_schema = tmp_path / "wrong-schema.json"
    wrong_schema.write_text(json.dumps({"schema_version": "2.0"}), encoding="utf-8")
    with pytest.raises(PlatformError, match="MODEL_PRICING_CATALOG_INVALID"):
        ModelPriceCatalog.from_path(wrong_schema, allowed_models=())

    invalid_rate = tmp_path / "invalid-rate.json"
    invalid_rate.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "currency": "USD",
                "catalog_version": "test",
                "models": {
                    "gpt-5.6-sol": {
                        "input_usd_per_million_tokens": "invalid",
                        "output_usd_per_million_tokens": "1",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(
        PlatformError,
        match="MODEL_PRICING_CATALOG_INVALID",
    ) as invalid_rate_error:
        ModelPriceCatalog.from_path(invalid_rate, allowed_models=())
    assert invalid_rate_error.value.code == "MODEL_PRICING_CATALOG_INVALID"
    assert isinstance(invalid_rate_error.value.__cause__, InvalidOperation)


def _openai_runtime(*, runner: Any = None, memory_vault: Any = None) -> OpenAIAgentRuntime:
    pricing = ModelPriceCatalog(
        catalog_version="test",
        models={
            "gpt-5.6-sol": ModelPrice(
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("1"),
            )
        },
    )
    return OpenAIAgentRuntime(
        factory=SimpleNamespace(),
        runner=runner or SimpleNamespace(run=lambda: None),
        context_builder=ContextBuilder(),
        known_capabilities=frozenset(),
        pricing=pricing,
        memory_vault=memory_vault,
    )


@pytest.mark.asyncio
async def test_openai_runtime_requires_budget_before_provider_invocation() -> None:
    runtime = _openai_runtime()
    with pytest.raises(PlatformError, match="BUDGET_CONTEXT_REQUIRED"):
        await runtime._run_model(
            SimpleNamespace(model="gpt-5.6-sol"),
            "{}",
            context=SimpleNamespace(),
            max_turns=1,
            role="planner",
            budget=None,
        )
    with pytest.raises(PlatformError, match="BUDGET_CONTEXT_REQUIRED"):
        runtime._budget(SimpleNamespace(budget=None))


def test_openai_runtime_usage_signature_and_model_name_fallbacks() -> None:
    runtime = _openai_runtime(runner=SimpleNamespace(run=object()))
    usage = runtime._extract_usage(
        SimpleNamespace(
            context_wrapper=SimpleNamespace(
                usage=SimpleNamespace(
                    input_tokens=3,
                    output_tokens=4,
                    input_tokens_details=SimpleNamespace(cached_tokens=2),
                )
            )
        )
    )

    assert usage == ModelUsage(input_tokens=3, output_tokens=4, cached_input_tokens=2)
    assert runtime._runner_accepts_hooks() is False
    assert runtime._non_negative_int(True) == 0
    assert runtime._non_negative_int(-1) == 0
    assert runtime._model_name(SimpleNamespace(model="gpt-5.6-sol")) == "gpt-5.6-sol"
    assert (
        runtime._model_name(SimpleNamespace(model=SimpleNamespace(model="gpt-5.6-sol")))
        == "gpt-5.6-sol"
    )
    assert (
        runtime._model_name(SimpleNamespace(model=SimpleNamespace(model_name="gpt-5.6-sol")))
        == "gpt-5.6-sol"
    )
    assert runtime._model_name(SimpleNamespace()) == "unknown"


@pytest.mark.asyncio
async def test_openai_memory_failures_are_wrapped_without_losing_cause() -> None:
    contract = _contract(scopes={"knowledge:read", "memory:read"})
    with pytest.raises(PlatformError, match="MEMORY_CONTEXT_READER_REQUIRED"):
        await _openai_runtime()._memory_blocks(contract)

    class _PlatformFailureVault:
        async def list_for_context(self, **_: Any) -> Any:
            raise PlatformError(
                "MEMORY_BACKEND_BUSY",
                "retry later",
                retryable=True,
            )

    with pytest.raises(PlatformError) as platform_error:
        await _openai_runtime(memory_vault=_PlatformFailureVault())._memory_blocks(contract)
    assert platform_error.value.code == "MEMORY_CONTEXT_UNAVAILABLE"
    assert platform_error.value.context == {"cause_code": "MEMORY_BACKEND_BUSY"}

    class _UnexpectedFailureVault:
        async def list_for_context(self, **_: Any) -> Any:
            raise RuntimeError("socket closed")

    with pytest.raises(PlatformError) as unexpected:
        await _openai_runtime(memory_vault=_UnexpectedFailureVault())._memory_blocks(contract)
    assert unexpected.value.context == {"cause_type": "RuntimeError"}
    assert unexpected.value.retryable is True


def test_openai_context_purpose_and_incomplete_manifest_are_fail_closed() -> None:
    runtime = _openai_runtime()
    assert (
        runtime._memory_purpose(_contract(constraints={"purpose": "  investigation  "}))
        == "investigation"
    )
    assert runtime._memory_purpose(_contract()) == "FinalResponse@1.0"

    assembly = ContextAssembly(
        items=(),
        manifest={
            "complete": False,
            "manifest_hash": "a" * 64,
            "omitted_sources": ["memory:1"],
        },
    )
    with pytest.raises(ContextAssemblyError, match="CONTEXT_ASSEMBLY_INCOMPLETE"):
        runtime._model_input(assembly)


def test_verifier_reports_every_provenance_failure_mode() -> None:
    criteria = [
        SuccessCriterion(
            id="optional",
            description="Optional check.",
            severity="should",
            verification="schema",
        ),
        SuccessCriterion(
            id="missing-evidence",
            description="Evidence is present.",
            verification="schema",
            evidence_required=True,
        ),
        SuccessCriterion(
            id="inaccessible",
            description="Referenced evidence is accessible.",
            verification="schema",
        ),
        SuccessCriterion(
            id="unversioned-environment",
            description="Environment is verified.",
            verification="environment",
        ),
        SuccessCriterion(
            id="untrusted-human",
            description="Human review is trusted.",
            verification="human",
        ),
    ]
    environment_evidence = Evidence(
        source_type="environment",
        source_id="health",
        locator="https://service.example.test/health",
        captured_at=datetime.now(UTC),
        content_hash="b" * 64,
        supports_criterion_ids=["unversioned-environment"],
        trust="trusted",
    )
    human_evidence = Evidence(
        source_type="human_review",
        source_id="review-1",
        locator="review:1",
        captured_at=datetime.now(UTC),
        content_hash="c" * 64,
        supports_criterion_ids=["untrusted-human"],
        trust="untrusted",
    )
    checks = [
        CriterionVerification(
            criterion_id="missing-evidence",
            method="schema",
            passed=True,
            checked_at=datetime.now(UTC),
        ),
        CriterionVerification(
            criterion_id="inaccessible",
            method="schema",
            passed=True,
            checked_at=datetime.now(UTC),
            evidence_ids=[uuid4()],
        ),
        CriterionVerification(
            criterion_id="unversioned-environment",
            method="environment",
            passed=True,
            checked_at=datetime.now(UTC),
            evidence_ids=[environment_evidence.evidence_id],
        ),
        CriterionVerification(
            criterion_id="untrusted-human",
            method="human",
            passed=True,
            checked_at=datetime.now(UTC),
            evidence_ids=[human_evidence.evidence_id],
            verifier_version="human-review@1",
        ),
    ]
    output = WorkerOutput.model_construct(
        summary="provenance failures",
        claims=[],
        evidence=[environment_evidence, human_evidence],
        criterion_verifications=checks,
        action_proposals=[],
        artifacts=[],
        uncertainties=[],
    )

    findings = deterministic_verification_findings(
        _contract(criteria=criteria),
        {"final": output},
    )

    assert findings["failed_criteria"] == [
        "missing-evidence",
        "inaccessible",
        "unversioned-environment",
        "untrusted-human",
    ]
    assert findings["unsupported_claim_ids"] == []
    assert findings["requires_escalation"] is True
    assert any("inaccessible evidence" in item for item in findings["hard_failures"])
    assert any("no versioned environment" in item for item in findings["hard_failures"])
    assert any("untrusted evidence" in item for item in findings["hard_failures"])
