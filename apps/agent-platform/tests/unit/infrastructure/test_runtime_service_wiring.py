from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from agent_platform.api.schemas import (
    BudgetRequest,
    CreateRunRequest,
    RequestedOutput,
    SuccessCriterionRequest,
)
from agent_platform.application.action_service import ActionService
from agent_platform.application.commit_service import CommitService
from agent_platform.application.errors import Conflict
from agent_platform.application.run_service import RunService
from agent_platform.domain.enums import RiskLevel, RunStatus, ToolEffect
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.infrastructure.observability.metrics import PlatformMetrics
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.models import (
    PolicyDecision,
    RegisteredTool,
    ToolContext,
    ToolDefinition,
)
from agent_platform.tools.registry import ToolRegistry


class _Workflow:
    async def start(
        self,
        run_id: object,
        tenant_id: str,
        correlation_id: str,
        *,
        contract: object,
    ) -> None:
        del run_id, tenant_id, correlation_id, contract

    async def notify_action(
        self,
        action_id: object,
        tenant_id: str,
        decision: str,
    ) -> None:
        del action_id, tenant_id, decision


class _Policy:
    async def authorize_tool(self, request: dict[str, object]) -> PolicyDecision:
        tool = request["tool"]
        assert isinstance(tool, dict)
        approval_required = tool["effect"] == "prepare"
        return self._decision(approval_required=approval_required)

    async def authorize_action(self, request: dict[str, object]) -> PolicyDecision:
        del request
        return self._decision(approval_required=False)

    @staticmethod
    def _decision(*, approval_required: bool) -> PolicyDecision:
        return PolicyDecision(
            allowed=True,
            reason_codes=(),
            approval_required=approval_required,
            policy_version="test-1",
            credential_scopes=frozenset({"knowledge:read", "email:commit"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class _Credentials:
    async def issue(
        self,
        tenant_id: str,
        principal_id: str,
        scopes: frozenset[str],
        ttl_seconds: int,
    ) -> dict[str, object]:
        del principal_id
        return {"tenant": tenant_id, "scopes": scopes, "ttl": ttl_seconds}


class _Adapter:
    def __init__(self) -> None:
        self.verify_passed = True

    async def read(self, args: object, credential: object) -> object:
        del args, credential
        return {"items": [{"title": "source"}]}

    async def preview(self, args: object, credential: object) -> object:
        del credential
        return {"preview": args}

    async def lookup_by_idempotency_key(self, key: str, credential: object) -> object | None:
        del key, credential
        return None

    async def commit(self, payload: object, credential: object, key: str) -> object:
        del payload, credential
        return {
            "external_operation_id": "mail-1",
            "committed_at": datetime.now(UTC).isoformat(),
            "idempotency_key": key,
        }

    async def verify(self, action: object, receipt: object, credential: object) -> object:
        del action, receipt, credential
        return {
            "passed": self.verify_passed,
            "verified_at": datetime.now(UTC).isoformat(),
            "method": "read_after_write",
        }

    async def compensate(self, action: object, receipt: object, credential: object) -> object:
        del action, receipt, credential
        return {"compensated": True}


def _definition(name: str, effect: ToolEffect, required_scope: str) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version="1.0.0",
        description="Bounded observability test tool",
        capability_name=name,
        effect=effect,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk=RiskLevel.HIGH if effect == ToolEffect.PREPARE else RiskLevel.MEDIUM,
        required_scopes=frozenset({required_scope}),
        supported_data_classes=frozenset({"internal"}),
        timeout_seconds=2,
        max_result_bytes=4_096,
        idempotency="business_key" if effect == ToolEffect.PREPARE else "none",
        approval_policy="human" if effect == ToolEffect.PREPARE else "none",
        adapter_ref="test",
    )


def _principal() -> Principal:
    return Principal(
        user_id="requester",
        tenant_id="tenant-a",
        roles=frozenset({"analyst"}),
        scopes=frozenset({"runs:create", "knowledge:read", "email:commit"}),
        auth_strength="mfa",
    )


def _scope() -> DataScope:
    return DataScope(
        tenant_id="tenant-a",
        resource_types=frozenset({"knowledge", "email"}),
        classifications=frozenset({"internal"}),
    )


@pytest.mark.asyncio
async def test_run_lifecycle_records_acceptance_terminal_duration_cost_and_budget() -> None:
    registry = CollectorRegistry()
    observability = RuntimeObservability(PlatformMetrics(registry), environment="test")
    store = InMemoryPlatformStore()
    service = RunService(
        store.runs,
        store.actions,
        _Workflow(),
        observability=observability,
    )
    request = CreateRunRequest(
        goal="Create a source-backed report",
        success_criteria=[
            SuccessCriterionRequest(
                id="sc-1",
                description="Every key claim has evidence",
                severity="must",
            )
        ],
        allowed_capabilities=["knowledge.search"],
        constraints={"use_case": "knowledge-report", "tenant_tier": "standard"},
        budget=BudgetRequest(
            max_cost_usd=Decimal("5"),
            max_duration_seconds=300,
            max_tool_calls=7,
        ),
        external_write_policy="deny",
        requested_output=RequestedOutput(format="market_report@1.0"),
    )

    run, created = await service.create(
        request,
        _principal(),
        _scope(),
        idempotency_key="request-1",
        correlation_id="corr-1",
    )
    _, duplicate_created = await service.create(
        request,
        _principal(),
        _scope(),
        idempotency_key="request-1",
        correlation_id="corr-2",
    )
    await service.transition(
        run.run_id,
        "tenant-a",
        RunStatus.FAILED,
        "corr-3",
        reason_code="TEST_FAILURE",
    )

    assert created is True
    assert duplicate_created is False
    output = generate_latest(registry).decode()
    assert 'agent_run_accept_requests_total{environment="test",outcome="accepted"} 2.0' in output
    assert (
        'agent_runs_total{environment="test",risk="medium",status="received",'
        'tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output
    assert (
        'agent_runs_total{environment="test",risk="medium",status="failed",'
        'tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output
    assert (
        'agent_budget_utilization_ratio_count{budget_type="cost",environment="test",'
        'tenant_tier="standard",use_case="knowledge-report"} 1.0'
    ) in output


@pytest.mark.asyncio
async def test_tool_policy_action_approval_commit_and_verification_are_instrumented() -> None:
    registry = CollectorRegistry()
    observability = RuntimeObservability(PlatformMetrics(registry), environment="test")
    store = InMemoryPlatformStore()
    adapter = _Adapter()
    tools = ToolRegistry()
    tools.register(
        RegisteredTool(
            _definition("knowledge.search", ToolEffect.READ, "knowledge:read"),
            adapter,
        )
    )
    tools.register(
        RegisteredTool(
            _definition("email.prepare", ToolEffect.PREPARE, "email:commit"),
            adapter,
        )
    )
    policy = _Policy()
    credentials = _Credentials()
    gateway = ToolGateway(
        tools,
        policy,
        credentials,
        store.actions,
        store.artifacts,
        observability=observability,
    )
    run_service = RunService(store.runs, store.actions, _Workflow())
    request = CreateRunRequest(
        goal="Prepare an approved message",
        success_criteria=[
            SuccessCriterionRequest(
                id="sc-1",
                description="Message is prepared",
                severity="must",
            )
        ],
        allowed_capabilities=["knowledge.search", "email.prepare"],
        budget=BudgetRequest(
            max_cost_usd=Decimal("2"),
            max_duration_seconds=60,
            max_tool_calls=5,
        ),
        external_write_policy="approval",
        requested_output=RequestedOutput(format="message@1.0"),
    )
    run, _ = await run_service.create(
        request,
        _principal(),
        _scope(),
        idempotency_key="request-2",
        correlation_id="corr-1",
    )
    context = ToolContext(
        run_id=run.run_id,
        task_id="analysis",
        plan_version=1,
        tenant_id="tenant-a",
        principal_id="requester",
        principal_scopes=frozenset({"knowledge:read", "email:commit"}),
        allowed_capabilities=frozenset({"knowledge.search", "email.prepare"}),
        data_scope={"classifications": ["internal"]},
        correlation_id="corr-1",
    )

    await gateway.call_read(context, "knowledge.search", {"query": "source"})
    action = await gateway.prepare(context, "email.prepare", {"query": "draft"})
    await ActionService(
        store.actions,
        _Workflow(),
        observability=observability,
    ).decide(
        action.action_id,
        tenant_id="tenant-a",
        actor_id="approver",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=action.payload_hash,
        comment=None,
    )
    await CommitService(
        store.actions,
        store.runs,
        tools,
        policy,
        credentials,
        observability=observability,
    ).commit(
        tenant_id="tenant-a",
        principal_id="commit-worker",
        principal_scopes=frozenset({"email:commit"}),
        action_id=action.action_id,
        correlation_id="corr-commit",
    )

    output = generate_latest(registry).decode()
    assert (
        'agent_tool_calls_total{effect="read",environment="test",status="success",'
        'tool="knowledge.search",version="1.0.0"} 1.0'
    ) in output
    assert (
        'agent_policy_decisions_total{decision="allow",environment="test",'
        'phase="commit",reason_code="allowed"} 1.0'
    ) in output
    assert (
        'agent_actions_total{action_type="email.prepare",environment="test",risk="high",'
        'status="committed"} 1.0'
    ) in output
    assert (
        'agent_approvals_duration_seconds_count{decision="approved",environment="test",'
        'policy="human"} 1.0'
    ) in output

    next_action = await gateway.prepare(context, "email.prepare", {"query": "bad draft"})
    await ActionService(
        store.actions,
        _Workflow(),
        observability=observability,
    ).decide(
        next_action.action_id,
        tenant_id="tenant-a",
        actor_id="approver-2",
        actor_roles=frozenset({"approver"}),
        auth_strength="phishing_resistant",
        decision="approved",
        expected_payload_hash=next_action.payload_hash,
        comment=None,
    )
    adapter.verify_passed = False
    with pytest.raises(Conflict, match="SIDE_EFFECT_VERIFICATION_FAILED"):
        await CommitService(
            store.actions,
            store.runs,
            tools,
            policy,
            credentials,
            observability=observability,
        ).commit(
            tenant_id="tenant-a",
            principal_id="commit-worker",
            principal_scopes=frozenset({"email:commit"}),
            action_id=next_action.action_id,
            correlation_id="corr-verify-failed",
        )
    output = generate_latest(registry).decode()
    assert (
        'agent_verification_failures_total{environment="test",'
        'reason="SIDE_EFFECT_VERIFICATION_FAILED",verifier="side_effect"} 1.0'
    ) in output


def test_observability_api_cannot_accept_high_cardinality_identity_labels() -> None:
    parameters = RuntimeObservability.record_tool.__annotations__
    assert "tenant_id" not in parameters
    assert "run_id" not in parameters
    assert "user_id" not in parameters
