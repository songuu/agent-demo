from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from agent_platform.domain.enums import RiskLevel, ToolEffect
from agent_platform.infrastructure.memory_store import InMemoryPlatformStore
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.models import (
    PolicyDecision,
    RegisteredTool,
    ToolContext,
    ToolDefinition,
)
from agent_platform.tools.registry import ToolRegistry


class FakePolicy:
    def __init__(self, *, allowed: bool = True, approval_required: bool = False) -> None:
        self.allowed = allowed
        self.approval_required = approval_required

    async def authorize_tool(self, request: object) -> PolicyDecision:
        return PolicyDecision(
            allowed=self.allowed,
            reason_codes=() if self.allowed else ("denied_by_test",),
            approval_required=self.approval_required,
            policy_version="test-1",
            credential_scopes=frozenset({"knowledge:read"}),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )

    async def authorize_action(self, request: object) -> PolicyDecision:
        return await self.authorize_tool(request)


class FakeCredentials:
    async def issue(
        self, tenant_id: str, principal_id: str, scopes: frozenset[str], ttl_seconds: int
    ) -> dict[str, object]:
        return {"tenant_id": tenant_id, "scopes": scopes, "ttl": ttl_seconds}


class FakeAdapter:
    def __init__(self, result: object = None) -> None:
        self.result = {"items": [{"title": "source"}]} if result is None else result
        self.read_calls = 0
        self.preview_calls = 0

    async def read(self, args: object, credential: object) -> object:
        self.read_calls += 1
        return self.result

    async def preview(self, args: object, credential: object) -> dict[str, object]:
        self.preview_calls += 1
        return {"normalized": args, "side_effect": "none_until_commit"}

    async def lookup_by_idempotency_key(self, key: str, credential: object) -> None:
        return None

    async def commit(self, payload: object, credential: object, key: str) -> object:
        return {"external_operation_id": key}

    async def verify(self, action: object, receipt: object, credential: object) -> object:
        return {"passed": True}

    async def compensate(self, action: object, receipt: object, credential: object) -> object:
        return {"compensated": True}


def definition(
    name: str = "knowledge.search",
    *,
    effect: ToolEffect = ToolEffect.READ,
    max_result_bytes: int = 1024,
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version="1.0.0",
        description="Bounded test tool",
        capability_name=name,
        effect=effect,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk=RiskLevel.MEDIUM,
        required_scopes=frozenset({"knowledge:read"}),
        supported_data_classes=frozenset({"internal"}),
        allowed_network_targets=(),
        timeout_seconds=1,
        max_result_bytes=max_result_bytes,
        idempotency="none" if effect == ToolEffect.READ else "business_key",
        approval_policy="human" if effect == ToolEffect.PREPARE else "none",
        adapter_ref="test",
    )


def context() -> ToolContext:
    return ToolContext(
        run_id=uuid4(),
        task_id="task-1",
        plan_version=1,
        tenant_id="tenant-a",
        principal_id="user-1",
        principal_scopes=frozenset({"knowledge:read"}),
        allowed_capabilities=frozenset({"knowledge.search", "email.prepare"}),
        data_scope={"tenant_id": "tenant-a"},
        correlation_id="corr-1",
    )


@pytest.mark.asyncio
async def test_unknown_tool_extra_argument_and_wrong_effect_are_denied() -> None:
    store = InMemoryPlatformStore()
    registry = ToolRegistry()
    adapter = FakeAdapter()
    registry.register(RegisteredTool(definition(), adapter))
    gateway = ToolGateway(registry, FakePolicy(), FakeCredentials(), store.actions, store.artifacts)

    with pytest.raises(Exception, match="TOOL_NOT_FOUND"):
        await gateway.call_read(context(), "unknown", {"query": "x"})
    with pytest.raises(Exception, match="SCHEMA_VALIDATION_FAILED"):
        await gateway.call_read(context(), "knowledge.search", {"query": "x", "unexpected": True})

    registry.register(
        RegisteredTool(definition("email.prepare", effect=ToolEffect.PREPARE), adapter)
    )
    with pytest.raises(Exception, match="READ_EFFECT_REQUIRED"):
        await gateway.call_read(context(), "email.prepare", {"query": "x"})
    assert adapter.read_calls == 0


@pytest.mark.asyncio
async def test_large_read_result_is_artifactized_and_not_returned_inline() -> None:
    store = InMemoryPlatformStore()
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            definition(max_result_bytes=50),
            FakeAdapter({"items": [{"content": "x" * 500}]}),
        )
    )
    gateway = ToolGateway(registry, FakePolicy(), FakeCredentials(), store.actions, store.artifacts)

    result = await gateway.call_read(context(), "knowledge.search", {"query": "x"})

    assert result.truncated is True
    assert result.artifact_id is not None
    assert result.data is None
    artifact = await store.artifacts.get(result.artifact_id, "tenant-a")
    assert len(artifact.content) > 50
    assert artifact.retention_policy == "tool-raw-short@1:artifact:90d"
    assert artifact.expires_at is not None
    assert artifact.expires_at > datetime.now(UTC) + timedelta(days=89)
    assert artifact.scan_status == "trusted_generated"
    assert artifact.scan_provenance["trusted_generated"]["source"] == "tool_gateway"


@pytest.mark.asyncio
async def test_prepare_creates_hash_bound_action_without_committing() -> None:
    store = InMemoryPlatformStore()
    registry = ToolRegistry()
    adapter = FakeAdapter()
    registry.register(
        RegisteredTool(definition("email.prepare", effect=ToolEffect.PREPARE), adapter)
    )
    gateway = ToolGateway(
        registry,
        FakePolicy(approval_required=True),
        FakeCredentials(),
        store.actions,
        store.artifacts,
    )

    action = await gateway.prepare(context(), "email.prepare", {"query": "approved draft"})

    assert action.status.value == "pending_approval"
    assert len(action.payload_hash) == 64
    assert action.canonical_payload == {"query": "approved draft"}
    assert adapter.preview_calls == 1


def test_agent_catalog_never_exposes_commit_effect() -> None:
    registry = ToolRegistry()
    registry.register(RegisteredTool(definition(), FakeAdapter()))
    with pytest.raises(ValueError, match="COMMIT_TOOL_NOT_AGENT_VISIBLE"):
        registry.register(
            RegisteredTool(
                definition("commit_action", effect=ToolEffect.COMMIT),
                FakeAdapter(),
            ),
            expose_to_agent=True,
        )


class CapturingActionRepository:
    def __init__(self) -> None:
        self.event = None
        self.invocation = None

    async def create_once_with_event(self, action, event, invocation):
        self.event = event
        self.invocation = invocation
        return action, True, event


@pytest.mark.asyncio
async def test_pending_prepare_emits_hash_bound_approval_required_event() -> None:
    actions = CapturingActionRepository()
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            definition("email.prepare", effect=ToolEffect.PREPARE),
            FakeAdapter(),
        )
    )
    gateway = ToolGateway(
        registry,
        FakePolicy(approval_required=True),
        FakeCredentials(),
        actions,
        InMemoryPlatformStore().artifacts,
        audit=object(),
    )
    tool_context = context()

    action = await gateway.prepare(
        tool_context,
        "email.prepare",
        {"query": "approved draft"},
    )

    assert actions.event is not None
    assert actions.invocation is not None
    assert actions.event.event_type == "action.approval_required"
    assert actions.event.payload["run_id"] == str(tool_context.run_id)
    assert actions.event.payload["action_id"] == str(action.action_id)
    assert actions.event.payload["risk"] == RiskLevel.MEDIUM.value
    assert actions.event.payload["payload_hash"] == action.payload_hash
    assert actions.event.payload["expires_at"] == action.expires_at.isoformat()
    assert actions.event.payload["preview_locator"] == {
        "storage": "action_record",
        "action_id": str(action.action_id),
        "field": "preview",
    }
    assert actions.event.payload["preview_hash"] == actions.invocation.result_hash
    assert "preview" not in actions.event.payload


@pytest.mark.asyncio
async def test_approved_prepare_keeps_prepared_event_type() -> None:
    actions = CapturingActionRepository()
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            definition("email.prepare", effect=ToolEffect.PREPARE),
            FakeAdapter(),
        )
    )
    gateway = ToolGateway(
        registry,
        FakePolicy(approval_required=False),
        FakeCredentials(),
        actions,
        InMemoryPlatformStore().artifacts,
        audit=object(),
    )

    action = await gateway.prepare(
        context(),
        "email.prepare",
        {"query": "no approval needed"},
    )

    assert action.status.value == "approved"
    assert actions.event is not None
    assert actions.event.event_type == "action.prepared"
