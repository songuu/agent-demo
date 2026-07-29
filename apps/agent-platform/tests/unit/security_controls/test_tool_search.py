from __future__ import annotations

import pytest

from agent_platform.domain.enums import RiskLevel, ToolEffect
from agent_platform.tools.models import ToolDefinition
from agent_platform.tools.search import (
    SearchableTool,
    ToolSearchContext,
    ToolSearchIndex,
)


def definition(
    name: str,
    capability: str,
    *,
    effect: ToolEffect = ToolEffect.READ,
    description: str = "Search source-backed enterprise knowledge",
) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        version="1.0.0",
        description=description,
        capability_name=capability,
        effect=effect,
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


def test_tool_search_filters_tenant_task_capability_and_is_stable() -> None:
    index = ToolSearchIndex()
    index.register(
        SearchableTool(
            tenant_id="tenant-a",
            allowed_task_ids=frozenset({"research-a"}),
            definition=definition("knowledge.search", "knowledge.search"),
        )
    )
    index.register(
        SearchableTool(
            tenant_id="tenant-b",
            allowed_task_ids=frozenset({"research-a"}),
            definition=definition("secret.search", "secret.search"),
        )
    )

    context = ToolSearchContext(
        tenant_id="tenant-a",
        task_id="research-a",
        allowed_capabilities=frozenset({"knowledge.search"}),
        allowed_tool_names=frozenset({"knowledge.search"}),
    )
    first = index.search("enterprise knowledge", context)
    second = index.search("enterprise knowledge", context)

    assert [result.definition.name for result in first] == ["knowledge.search"]
    assert first == second
    assert (
        index.search(
            "enterprise knowledge",
            context.model_copy(update={"task_id": "other-task"}),
        )
        == ()
    )
    assert (
        index.search(
            "enterprise knowledge",
            context.model_copy(update={"allowed_capabilities": frozenset()}),
        )
        == ()
    )


def test_commit_tools_can_never_enter_search_catalog() -> None:
    index = ToolSearchIndex()
    with pytest.raises(ValueError, match="TOOL_SEARCH_COMMIT_FORBIDDEN"):
        index.register(
            SearchableTool(
                tenant_id="tenant-a",
                allowed_task_ids=frozenset({"research-a"}),
                definition=definition(
                    "payments.commit",
                    "payments.commit",
                    effect=ToolEffect.COMMIT,
                ),
            )
        )
