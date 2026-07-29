from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.reliability import BackpressureGate
from agent_platform.application.trajectory_monitor import (
    TrajectoryMonitor,
    TrajectorySnapshot,
)
from agent_platform.domain.enums import RiskLevel, ToolEffect, TrajectoryAction
from agent_platform.infrastructure.cache import CacheKey, SafeCache
from agent_platform.infrastructure.sandbox import SandboxJobRequest
from agent_platform.tools.mcp import McpRegistry
from agent_platform.tools.models import ToolContext, ToolDefinition
from agent_platform.tools.programmatic import (
    ProgrammaticCall,
    ProgrammaticPlan,
    ProgrammaticReadExecutor,
)
from agent_platform.tools.search import SearchableTool, ToolSearchContext, ToolSearchIndex

from .test_mcp import server


def tool_definition(version: str = "1.0.0") -> ToolDefinition:
    return ToolDefinition(
        name="knowledge.search",
        version=version,
        description=f"Knowledge search version {version}",
        capability_name="knowledge.search",
        effect=ToolEffect.READ,
        input_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk=RiskLevel.LOW,
        timeout_seconds=10,
        max_result_bytes=10_000,
        idempotency="none",
        approval_policy="none",
        adapter_ref="test",
    )


def tool_context() -> ToolContext:
    from uuid import uuid4

    return ToolContext(
        run_id=uuid4(),
        task_id="research-a",
        plan_version=1,
        tenant_id="tenant-a",
        principal_id="user-a",
        principal_scopes=frozenset({"knowledge:read"}),
        allowed_capabilities=frozenset({"knowledge.search"}),
        data_scope={"tenant_id": "tenant-a"},
        correlation_id="corr-a",
    )


def cache_key(tenant_id: str) -> CacheKey:
    return CacheKey.build(
        tenant_id=tenant_id,
        namespace="read-result",
        data_scope={"tenant_id": tenant_id},
        tool_id="knowledge.search",
        tool_version="1.0.0",
        model_id="openai:gpt-5.6",
        model_revision="2026-07-15",
        prompt_id="knowledge.search",
        prompt_digest="a" * 64,
        input_data={"q": tenant_id},
        freshness_token="fresh",
    )


def test_mcp_output_rejects_forged_authorized_call_endpoint() -> None:
    registry = McpRegistry()
    registry.register(server())
    call = registry.authorize_call(
        server_id="enterprise-knowledge",
        tenant_id="tenant-a",
        tool_name="knowledge.search",
        task_id="research-a",
        allowed_capabilities={"knowledge.search"},
    )
    forged = call.model_copy(update={"endpoint": "https://attacker.test/mcp"})

    with pytest.raises(PlatformError, match="MCP_CALL_NOT_REGISTERED"):
        registry.normalize_output(forged, {"items": []})


def test_tool_search_prefers_tenant_override_and_latest_version() -> None:
    index = ToolSearchIndex()
    index.register(
        SearchableTool(
            tenant_id="*",
            allowed_task_ids=frozenset({"*"}),
            definition=tool_definition("1.0.0"),
        )
    )
    index.register(
        SearchableTool(
            tenant_id="tenant-a",
            allowed_task_ids=frozenset({"research-a"}),
            definition=tool_definition("1.1.0"),
        )
    )
    results = index.search(
        "knowledge search",
        ToolSearchContext(
            tenant_id="tenant-a",
            task_id="research-a",
            allowed_capabilities=frozenset({"knowledge.search"}),
            allowed_tool_names=frozenset({"knowledge.search"}),
        ),
    )
    assert [result.definition.version for result in results] == ["1.1.0"]


@pytest.mark.asyncio
async def test_programmatic_executor_validates_strict_tool_schema() -> None:
    invoked = False

    async def resolve(name: str, tenant_id: str) -> ToolDefinition:
        return tool_definition()

    async def invoke(tool: ToolDefinition, args: dict[str, Any]) -> Any:
        nonlocal invoked
        invoked = True
        return {}

    with pytest.raises(PlatformError, match="PTC_SCHEMA_VALIDATION_FAILED"):
        await ProgrammaticReadExecutor(resolve, invoke).execute(
            ProgrammaticPlan(
                waves=(
                    (
                        ProgrammaticCall(
                            call_id="c1",
                            tool_name="knowledge.search",
                            args={"unexpected": True},
                        ),
                    ),
                )
            ),
            tool_context(),
        )
    assert invoked is False


@pytest.mark.asyncio
async def test_cache_tenant_invalidation_does_not_flush_other_tenants() -> None:
    cache = SafeCache()
    first = cache_key("tenant-a")
    second = cache_key("tenant-b")
    await cache.put(
        first,
        tenant_id="tenant-a",
        kind="read_result",
        value={"tenant": "a"},
        ttl_seconds=30,
    )
    await cache.put(
        second,
        tenant_id="tenant-b",
        kind="read_result",
        value={"tenant": "b"},
        ttl_seconds=30,
    )

    assert await cache.invalidate_tenant("tenant-a") == 1
    assert await cache.get(first, tenant_id="tenant-a") is None
    assert await cache.get(second, tenant_id="tenant-b") == {"tenant": "b"}


def test_moderate_goal_drift_warns_and_long_lived_credentials_are_rejected() -> None:
    decision = TrajectoryMonitor().evaluate(
        TrajectorySnapshot(
            goal_similarity=0.79,
            denied_scope_attempts=0,
            unplanned_tool_calls=0,
            injection_indicators=0,
            credential_access_attempts=0,
            classification_escalations=0,
            retry_count=0,
            sensitive_read_then_egress=False,
            evidence_event_ids=(11,),
        )
    )
    assert decision.action is TrajectoryAction.WARN

    with pytest.raises(ValueError, match="SANDBOX_SENSITIVE_ENV_FORBIDDEN"):
        SandboxJobRequest(
            tenant_id="tenant-a",
            run_id="run-a",
            task_id="task-a",
            namespace="sandboxes",
            image="registry.example.test/sandbox@sha256:" + "a" * 64,
            command=("python", "-m", "runner"),
            environment={"AWS_ACCESS_KEY_ID": "long-lived"},
        )


@pytest.mark.asyncio
async def test_backpressure_timeout_does_not_release_another_call_slot() -> None:
    gate = BackpressureGate(
        max_in_flight=1,
        max_queued=1,
        queue_timeout_seconds=0.01,
    )
    release = asyncio.Event()
    entered = asyncio.Event()

    async def hold() -> None:
        async with gate.slot():
            entered.set()
            await release.wait()

    first = asyncio.create_task(hold())
    await entered.wait()
    with pytest.raises(PlatformError, match="BACKPRESSURE_TIMEOUT"):
        async with gate.slot():
            pass
    assert gate.in_flight == 1
    release.set()
    await first
    async with gate.slot():
        assert gate.in_flight == 1
