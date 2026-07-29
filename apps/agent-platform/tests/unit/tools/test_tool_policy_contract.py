from __future__ import annotations

from uuid import uuid4

from agent_platform.domain.enums import RiskLevel, ToolEffect
from agent_platform.tools.gateway import ToolGateway
from agent_platform.tools.models import ToolContext, ToolDefinition


def test_tool_policy_request_matches_the_production_opa_schema() -> None:
    context = ToolContext(
        run_id=uuid4(),
        task_id="research",
        plan_version=2,
        tenant_id="tenant-a",
        principal_id="user-a",
        principal_scopes=frozenset({"knowledge:read"}),
        allowed_capabilities=frozenset({"knowledge.search"}),
        data_scope={
            "tenant_id": "tenant-a",
            "resource_types": ["knowledge"],
            "classifications": ["public", "internal"],
        },
        correlation_id="corr-1",
    )
    definition = ToolDefinition(
        name="knowledge.search",
        version="1.0.0",
        description="Tenant-scoped knowledge search.",
        capability_name="knowledge.search",
        effect=ToolEffect.READ,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        output_schema={"type": "object"},
        risk=RiskLevel.MEDIUM,
        required_scopes=frozenset({"knowledge:read"}),
        supported_data_classes=frozenset({"public", "internal"}),
        timeout_seconds=5,
        max_result_bytes=1_000,
        idempotency="none",
        approval_policy="none",
        adapter_ref="test",
    )

    request = ToolGateway._policy_request(
        context,
        definition,
        {"query": "bounded"},
        "execute",
    )

    assert request["caller"] == "agent"
    assert request["kill_switch"] == {"mode": "none"}
    assert request["run"]["allowed_capabilities"] == ["knowledge.search"]
    assert request["tool"]["capability_name"] == "knowledge.search"
    assert request["tool"]["enabled"] is True
    assert request["tool"]["required_scopes"] == ["knowledge:read"]
    assert request["tool"]["supported_data_classes"] == ["internal", "public"]
    assert request["request"]["classifications"] == ["public", "internal"]
