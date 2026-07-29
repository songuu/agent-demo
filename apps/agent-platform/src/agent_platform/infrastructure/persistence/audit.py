"""Atomic execution-audit persistence and tenant-scoped audit export."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from typing import Any, cast
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.application.errors import Conflict, NotFound
from agent_platform.application.records import (
    AuditEvent,
    EventRecord,
    PlanExecutionRecord,
    RunRecord,
    TaskExecutionRecord,
    ToolInvocationRecord,
)
from agent_platform.domain.hashing import canonical_json
from agent_platform.infrastructure.persistence.models import (
    Approval,
    Artifact,
    PreparedAction,
    RunEvent,
    TaskExecution,
    TaskStatus,
    ToolInvocation,
)
from agent_platform.infrastructure.persistence.models import (
    ExecutionPlan as ExecutionPlanRow,
)
from agent_platform.infrastructure.persistence.models import (
    ToolEffect as DatabaseToolEffect,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)


def _json_value(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _unwrapped_json(value: Mapping[str, Any] | None) -> Any:
    if value is None:
        return None
    if value.get("kind") == "json" and "value" in value:
        return value["value"]
    return dict(value)


async def append_tool_invocation(
    session: AsyncSession,
    invocation: ToolInvocationRecord,
) -> bool:
    """Insert one real gateway/commit invocation without inventing retries."""

    statement = (
        insert(ToolInvocation)
        .values(
            invocation_id=invocation.invocation_id,
            run_id=invocation.run_id,
            tenant_id=invocation.tenant_id,
            plan_version=invocation.plan_version,
            task_id=invocation.task_id,
            tool_name=invocation.tool_name,
            tool_version=invocation.tool_version,
            effect=DatabaseToolEffect(invocation.effect.value),
            args_hash=invocation.args_hash,
            args_redacted=_json_value(invocation.args_redacted),
            data_scope_hash=invocation.data_scope_hash,
            policy_decision_id=invocation.policy_decision_id,
            policy_version=invocation.policy_version,
            status=invocation.status,
            result_hash=invocation.result_hash,
            result_artifact_id=invocation.result_artifact_id,
            error_code=invocation.error_code,
            latency_ms=invocation.latency_ms,
            provider_request_id=invocation.provider_request_id,
            created_at=invocation.created_at,
            completed_at=invocation.completed_at,
        )
        .on_conflict_do_nothing(index_elements=[ToolInvocation.invocation_id])
        .returning(ToolInvocation.invocation_id)
    )
    return await session.scalar(statement) is not None


class PostgresAuditRepository:
    """Own execution records that must be correlated with immutable Run events."""

    def __init__(self, factory: AsyncSessionFactory, runs: Any) -> None:
        self._factory = factory
        self._runs = runs

    async def save_plan_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        plan: PlanExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]:
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored = await self._runs._save_in_session(session, run, expected_version)
            inserted = await session.scalar(
                insert(ExecutionPlanRow)
                .values(
                    plan_id=plan.plan_id,
                    run_id=plan.run_id,
                    tenant_id=plan.tenant_id,
                    plan_version=plan.plan_version,
                    schema_version=plan.schema_version,
                    plan_json=_json_value(plan.plan_json),
                    plan_hash=plan.plan_hash,
                    planner_model=plan.planner_model,
                    prompt_id=plan.prompt_id,
                    prompt_version=plan.prompt_version,
                    validation_status=plan.validation_status,
                    created_at=plan.created_at,
                )
                .on_conflict_do_nothing(
                    index_elements=[ExecutionPlanRow.run_id, ExecutionPlanRow.plan_version]
                )
                .returning(ExecutionPlanRow.plan_id)
            )
            if inserted is None:
                existing_hash = await session.scalar(
                    select(ExecutionPlanRow.plan_hash).where(
                        ExecutionPlanRow.run_id == plan.run_id,
                        ExecutionPlanRow.tenant_id == plan.tenant_id,
                        ExecutionPlanRow.plan_version == plan.plan_version,
                    )
                )
                if existing_hash != plan.plan_hash:
                    raise Conflict(
                        "PLAN_VERSION_CONFLICT",
                        "Plan version already exists with a different hash",
                        run_id=str(plan.run_id),
                        plan_version=plan.plan_version,
                    )
            recorded = await self._append_event(session, stored, event)
            await session.commit()
            return stored, recorded

    async def start_task(
        self,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> EventRecord | None:
        async with tenant_session(self._factory, execution.tenant_id) as session:
            await self._runs._require_run(
                session,
                execution.run_id,
                execution.tenant_id,
                lock=True,
            )
            inserted = await session.scalar(
                insert(TaskExecution)
                .values(**self._task_values(execution))
                .on_conflict_do_nothing(
                    index_elements=[
                        TaskExecution.run_id,
                        TaskExecution.plan_version,
                        TaskExecution.task_id,
                        TaskExecution.attempt,
                    ]
                )
                .returning(TaskExecution.task_execution_id)
            )
            if inserted is None:
                await session.commit()
                return None
            run = await self._runs._get_in_session(
                session,
                execution.run_id,
                execution.tenant_id,
            )
            recorded = await self._append_event(session, run, event)
            await session.commit()
            return recorded

    async def complete_task_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]:
        async with tenant_session(self._factory, run.tenant_id) as session:
            stored = await self._runs._save_in_session(session, run, expected_version)
            await self._update_task(session, execution)
            recorded = await self._append_event(session, stored, event)
            await session.commit()
            return stored, recorded

    async def finish_task(
        self,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> EventRecord:
        async with tenant_session(self._factory, execution.tenant_id) as session:
            await self._runs._require_run(
                session,
                execution.run_id,
                execution.tenant_id,
                lock=True,
            )
            await self._update_task(session, execution)
            run = await self._runs._get_in_session(
                session,
                execution.run_id,
                execution.tenant_id,
            )
            recorded = await self._append_event(session, run, event)
            await session.commit()
            return recorded

    async def record_tool(
        self,
        invocation: ToolInvocationRecord,
        event: AuditEvent,
    ) -> EventRecord:
        async with tenant_session(self._factory, invocation.tenant_id) as session:
            run = await self._runs._get_in_session(
                session,
                invocation.run_id,
                invocation.tenant_id,
            )
            inserted = await append_tool_invocation(session, invocation)
            if not inserted:
                raise Conflict(
                    "TOOL_INVOCATION_CONFLICT",
                    "Tool invocation identifier already exists",
                    invocation_id=str(invocation.invocation_id),
                )
            recorded = await self._append_event(session, run, event)
            await session.commit()
            return recorded

    async def export_run(self, run_id: UUID, tenant_id: str) -> Mapping[str, Any]:
        async with tenant_session(self._factory, tenant_id) as session:
            run = await self._runs._get_in_session(session, run_id, tenant_id)
            plan_rows = (
                await session.scalars(
                    select(ExecutionPlanRow)
                    .where(
                        ExecutionPlanRow.run_id == run_id,
                        ExecutionPlanRow.tenant_id == tenant_id,
                    )
                    .order_by(ExecutionPlanRow.plan_version)
                )
            ).all()
            task_rows = (
                await session.scalars(
                    select(TaskExecution)
                    .where(
                        TaskExecution.run_id == run_id,
                        TaskExecution.tenant_id == tenant_id,
                    )
                    .order_by(
                        TaskExecution.plan_version,
                        TaskExecution.task_id,
                        TaskExecution.attempt,
                    )
                )
            ).all()
            tool_rows = (
                await session.scalars(
                    select(ToolInvocation)
                    .where(
                        ToolInvocation.run_id == run_id,
                        ToolInvocation.tenant_id == tenant_id,
                    )
                    .order_by(ToolInvocation.created_at, ToolInvocation.invocation_id)
                )
            ).all()
            action_rows = (
                await session.scalars(
                    select(PreparedAction)
                    .where(
                        PreparedAction.run_id == run_id,
                        PreparedAction.tenant_id == tenant_id,
                    )
                    .order_by(PreparedAction.created_at, PreparedAction.action_id)
                )
            ).all()
            approval_rows = (
                await session.scalars(
                    select(Approval)
                    .join(PreparedAction, PreparedAction.action_id == Approval.action_id)
                    .where(
                        PreparedAction.run_id == run_id,
                        Approval.tenant_id == tenant_id,
                    )
                    .order_by(Approval.created_at, Approval.approval_id)
                )
            ).all()
            artifact_rows = (
                await session.scalars(
                    select(Artifact)
                    .where(Artifact.run_id == run_id, Artifact.tenant_id == tenant_id)
                    .order_by(Artifact.created_at, Artifact.artifact_id)
                )
            ).all()
            event_rows = (
                await session.scalars(
                    select(RunEvent)
                    .where(RunEvent.run_id == run_id, RunEvent.tenant_id == tenant_id)
                    .order_by(RunEvent.sequence_no)
                )
            ).all()

            approvals_by_action: dict[UUID, list[dict[str, Any]]] = defaultdict(list)
            for row in approval_rows:
                approvals_by_action[row.action_id].append(
                    {
                        "approval_id": str(row.approval_id),
                        "actor_id": row.actor_id,
                        "actor_roles": list(row.actor_roles),
                        "auth_strength": row.auth_strength,
                        "decision": row.decision.value,
                        "payload_hash": row.payload_hash,
                        "comment": row.comment,
                        "policy_version": row.policy_version,
                        "created_at": row.created_at.isoformat(),
                    }
                )

            return {
                "run_id": str(run_id),
                "tenant_id": tenant_id,
                "contract": _json_value(run.contract),
                "run_snapshot": {
                    "status": run.status.value,
                    "current_plan_version": run.current_plan_version,
                    "request_hash": run.request_hash,
                    "workflow_id": run.workflow_id,
                    "version": run.version,
                    "created_at": run.created_at.isoformat(),
                    "updated_at": run.updated_at.isoformat(),
                },
                "plans": [
                    {
                        "plan_id": str(row.plan_id),
                        "plan_version": row.plan_version,
                        "schema_version": row.schema_version,
                        "plan": row.plan_json,
                        "plan_hash": row.plan_hash,
                        "planner_model": row.planner_model,
                        "prompt_id": row.prompt_id,
                        "prompt_version": row.prompt_version,
                        "validation_status": row.validation_status,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in plan_rows
                ],
                "task_executions": [
                    {
                        "task_execution_id": str(row.task_execution_id),
                        "plan_version": row.plan_version,
                        "task_id": row.task_id,
                        "task_kind": row.task_kind,
                        "attempt": row.attempt,
                        "status": row.status.value,
                        "model_name": row.model_name,
                        "model_settings": row.model_settings,
                        "prompt_id": row.prompt_id,
                        "prompt_version": row.prompt_version,
                        "input_refs": row.input_refs,
                        "output": row.output_json,
                        "output_artifact_id": (
                            str(row.output_artifact_id) if row.output_artifact_id else None
                        ),
                        "error_code": row.error_code,
                        "usage": row.usage_json,
                        "started_at": row.started_at.isoformat() if row.started_at else None,
                        "completed_at": (
                            row.completed_at.isoformat() if row.completed_at else None
                        ),
                    }
                    for row in task_rows
                ],
                "tool_invocations": [
                    {
                        "invocation_id": str(row.invocation_id),
                        "plan_version": row.plan_version,
                        "task_id": row.task_id,
                        "tool_name": row.tool_name,
                        "tool_version": row.tool_version,
                        "effect": row.effect.value,
                        "args_hash": row.args_hash,
                        "args_redacted": row.args_redacted,
                        "data_scope_hash": row.data_scope_hash,
                        "policy_decision_id": row.policy_decision_id,
                        "policy_version": row.policy_version,
                        "status": row.status,
                        "result_hash": row.result_hash,
                        "result_artifact_id": (
                            str(row.result_artifact_id) if row.result_artifact_id else None
                        ),
                        "error_code": row.error_code,
                        "latency_ms": row.latency_ms,
                        "provider_request_id": row.provider_request_id,
                        "created_at": row.created_at.isoformat(),
                        "completed_at": (
                            row.completed_at.isoformat() if row.completed_at else None
                        ),
                    }
                    for row in tool_rows
                ],
                "actions": [
                    {
                        "action_id": str(row.action_id),
                        "action_type": row.action_type,
                        "tool_name": row.tool_name,
                        "tool_version": row.tool_version,
                        "payload_hash": row.payload_hash,
                        "preview": row.preview_json,
                        "risk": row.risk.value,
                        "approval_policy": row.approval_policy,
                        "required_approvals": row.required_approvals,
                        "status": row.status.value,
                        "idempotency_key": row.idempotency_key,
                        "policy_version": row.policy_version,
                        "receipt": _unwrapped_json(row.receipt_json),
                        "receipt_artifact_id": (
                            str(row.receipt_artifact_id) if row.receipt_artifact_id else None
                        ),
                        "verification": _unwrapped_json(row.verification_json),
                        "failure_code": row.failure_code,
                        "approvals": approvals_by_action.get(row.action_id, []),
                        "created_at": row.created_at.isoformat(),
                        "updated_at": row.updated_at.isoformat(),
                    }
                    for row in action_rows
                ],
                "artifacts": [
                    {
                        "artifact_id": str(row.artifact_id),
                        "task_id": row.task_id,
                        "kind": row.kind,
                        "uri": row.uri,
                        "media_type": row.media_type,
                        "size_bytes": row.size_bytes,
                        "sha256": row.sha256,
                        "classification": row.classification,
                        "source": row.source_json,
                        "created_by": row.created_by,
                        "retention_policy": row.retention_policy,
                        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                        "deleted_at": row.deleted_at.isoformat() if row.deleted_at else None,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in artifact_rows
                ],
                "events": [
                    {
                        "sequence_no": row.sequence_no,
                        "event_type": row.event_type,
                        "schema_version": row.schema_version,
                        "actor_type": row.actor_type,
                        "actor_id": row.actor_id,
                        "task_id": row.task_id,
                        "action_id": str(row.action_id) if row.action_id else None,
                        "payload": row.payload,
                        "payload_hash": row.payload_hash,
                        "correlation_id": row.correlation_id,
                        "created_at": row.created_at.isoformat(),
                    }
                    for row in event_rows
                ],
            }

    async def _append_event(
        self,
        session: AsyncSession,
        run: RunRecord,
        event: AuditEvent,
    ) -> EventRecord:
        return cast(
            EventRecord,
            await self._runs._append_event_in_session(
                session,
                run,
                event.event_type,
                event.payload,
                event.correlation_id,
                actor_type=event.actor_type,
                actor_id=event.actor_id,
                task_id=event.task_id,
                action_id=event.action_id,
            ),
        )

    @staticmethod
    def _task_values(execution: TaskExecutionRecord) -> dict[str, Any]:
        return {
            "task_execution_id": execution.task_execution_id,
            "run_id": execution.run_id,
            "tenant_id": execution.tenant_id,
            "plan_version": execution.plan_version,
            "task_id": execution.task_id,
            "task_kind": execution.task_kind,
            "attempt": execution.attempt,
            "status": TaskStatus(execution.status),
            "model_name": execution.model_name,
            "model_settings": _json_value(execution.model_settings),
            "prompt_id": execution.prompt_id,
            "prompt_version": execution.prompt_version,
            "input_refs": _json_value(execution.input_refs),
            "output_json": _json_value(execution.output_json),
            "output_artifact_id": execution.output_artifact_id,
            "error_code": execution.error_code,
            "usage_json": _json_value(execution.usage_json),
            "started_at": execution.started_at,
            "completed_at": execution.completed_at,
            "created_at": execution.created_at,
        }

    @staticmethod
    async def _update_task(
        session: AsyncSession,
        execution: TaskExecutionRecord,
    ) -> None:
        updated = await session.scalar(
            update(TaskExecution)
            .where(
                TaskExecution.task_execution_id == execution.task_execution_id,
                TaskExecution.run_id == execution.run_id,
                TaskExecution.tenant_id == execution.tenant_id,
            )
            .values(**PostgresAuditRepository._task_values(execution))
            .returning(TaskExecution.task_execution_id)
        )
        if updated is None:
            raise NotFound("task_execution", str(execution.task_execution_id))
