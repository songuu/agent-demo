from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from agents import RunContextWrapper, function_tool

from agent_platform.domain.models import DataScope, Principal
from agent_platform.tools.models import ToolContext


@dataclass(slots=True)
class AgentToolContext:
    run_id: UUID
    task_id: str
    plan_version: int
    principal: Principal
    data_scope: DataScope
    allowed_capabilities: frozenset[str]
    correlation_id: str
    gateway: Any


async def safe_tool_error(context: RunContextWrapper[AgentToolContext], error: Exception) -> str:
    # Detailed exceptions belong in the internal audit stream. The model only
    # receives a stable opaque reference and cannot infer policy internals.
    error_id = f"{context.context.run_id}:{context.context.task_id}:tool-error"
    return f"tool_failed; error_id={error_id}; retry only when the Task policy permits"


def _gateway_context(context: AgentToolContext) -> ToolContext:
    return ToolContext(
        run_id=context.run_id,
        task_id=context.task_id,
        plan_version=context.plan_version,
        tenant_id=context.principal.tenant_id,
        principal_id=context.principal.user_id,
        principal_scopes=context.principal.scopes,
        allowed_capabilities=context.allowed_capabilities,
        data_scope=context.data_scope.model_dump(mode="json"),
        correlation_id=context.correlation_id,
    )


@function_tool(
    timeout=15.0,
    failure_error_function=safe_tool_error,
    strict_mode=True,
)
async def knowledge_search(
    context: RunContextWrapper[AgentToolContext],
    query: str,
    limit: int = 8,
) -> str:
    """Search authorized knowledge and return a bounded source manifest.

    Args:
        query: A concrete search query derived from the assigned task.
        limit: Maximum number of results, from 1 through 20.
    """

    result = await context.context.gateway.call_read(
        _gateway_context(context.context),
        "knowledge.search",
        {"query": query, "limit": min(max(limit, 1), 20)},
    )
    return str(result.model_dump_json())


@function_tool(
    timeout=15.0,
    failure_error_function=safe_tool_error,
    strict_mode=True,
)
async def prepare_email(
    context: RunContextWrapper[AgentToolContext],
    recipients: list[str],
    subject: str,
    body: str,
    artifact_ids: list[str] | None = None,
) -> str:
    """Prepare an email preview; this never sends a message.

    Args:
        recipients: Approved sandbox or enterprise recipient addresses.
        subject: Email subject.
        body: Evidence-backed email body.
        artifact_ids: Final Artifact identifiers to attach after approval.
    """

    action = await context.context.gateway.prepare(
        _gateway_context(context.context),
        "email.prepare",
        {
            "recipients": recipients,
            "subject": subject,
            "body": body,
            "artifact_ids": artifact_ids or [],
        },
    )
    return (
        f'{{"action_id":"{action.action_id}","status":"{action.status.value}",'
        f'"payload_hash":"{action.payload_hash}","preview":'
        f"{action.preview!r}}}"
    )


AGENT_FUNCTION_TOOLS = {
    "knowledge.search": knowledge_search,
    "email.prepare": prepare_email,
}
