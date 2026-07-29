"""Temporal Activity bridge to application services and bounded Agent runtime."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from time import monotonic
from typing import Any, TypeVar, cast
from uuid import UUID, uuid4, uuid5

from temporalio import activity
from temporalio.exceptions import ApplicationError

from agent_platform.agents.deterministic_runtime import RuntimeExecutionContext
from agent_platform.agents.verification import (
    aggregate_final_criterion_verifications,
    deterministic_verification_findings,
)
from agent_platform.application.dag_scheduler import BudgetLedger, RuntimeUsage
from agent_platform.application.errors import PlatformError
from agent_platform.application.records import (
    AuditEvent,
    PlanExecutionRecord,
    TaskExecutionRecord,
)
from agent_platform.application.trajectory_monitor import (
    TrajectoryCandidate,
    TrajectoryCheck,
)
from agent_platform.domain.enums import (
    ActionStatus,
    DataClassification,
    RunStatus,
)
from agent_platform.domain.events import RunEventType, action_expired_event_payload
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    ArtifactRef,
    CommitReceipt,
    ExecutionPlan,
    FinalResponse,
    TaskSpec,
    VerificationReport,
    VerificationResult,
    WorkerOutput,
)
from agent_platform.infrastructure.observability.runtime import RuntimeObservability

T = TypeVar("T")
TERMINAL_RUN_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.FAILED,
    RunStatus.CANCELLED,
}


@dataclass(slots=True)
class ActivityDependencies:
    store: Any
    runtime: Any
    gateway: Any
    run_service: Any
    commit_service: Any
    commit_scopes: frozenset[str] = frozenset()
    trajectory_guard: Any | None = None
    observability: RuntimeObservability | None = None

    @classmethod
    def from_container(cls, container: Any) -> ActivityDependencies:
        return cls(
            store=container.store,
            runtime=container.runtime,
            gateway=container.gateway,
            run_service=container.run_service,
            commit_service=container.commit_service,
            trajectory_guard=getattr(container, "trajectory_guard", None),
            observability=getattr(container, "observability", None),
        )


class TemporalActivities:
    """Idempotent Activity implementations registered on the Agent worker."""

    def __init__(self, dependencies: ActivityDependencies) -> None:
        self._deps = dependencies

    @activity.defn(name="agent.classify_contract")
    async def classify_contract(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status == RunStatus.RECEIVED:
                await self._transition(payload, RunStatus.CLASSIFIED)
            return {"status": "classified"}

        return await self._guard(operation())

    @activity.defn(name="agent.create_plan")
    async def create_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.plan is not None and run.current_plan_version > 0:
                return cast(dict[str, Any], run.plan.model_dump(mode="json"))
            if run.status == RunStatus.CLASSIFIED:
                run = await self._transition(payload, RunStatus.PLANNING)
            plan = await self._invoke_runtime(
                payload,
                run,
                lambda context: self._deps.runtime.plan(context, run.contract),
                role="planner",
                task_id="planner",
            )
            run = await self._run(payload)
            expected_version = run.version
            plan_payload = cast(dict[str, Any], plan.model_dump(mode="json"))
            plan_digest = payload_hash(plan_payload)
            metadata = self._runtime_audit_metadata("planner", run)
            run.plan = plan
            run.current_plan_version = plan.plan_version
            run.updated_at = datetime.now(UTC)
            await self._deps.store.audit.save_plan_with_run(
                run,
                expected_version,
                PlanExecutionRecord(
                    plan_id=plan.plan_id,
                    run_id=run.run_id,
                    tenant_id=run.tenant_id,
                    plan_version=plan.plan_version,
                    schema_version=plan.schema_version,
                    plan_json=plan_payload,
                    plan_hash=plan_digest,
                    planner_model=metadata["model_name"],
                    prompt_id=metadata["prompt_id"],
                    prompt_version=metadata["prompt_version"],
                ),
                AuditEvent(
                    event_type="plan.created",
                    payload={
                        "plan_id": str(plan.plan_id),
                        "plan_version": plan.plan_version,
                        "plan_hash": plan_digest,
                        "task_count": len(plan.tasks),
                        "model_name": metadata["model_name"],
                        "model_settings": metadata["model_settings"],
                        "prompt_id": metadata["prompt_id"],
                        "prompt_version": metadata["prompt_version"],
                    },
                    correlation_id=str(payload["correlation_id"]),
                    actor_type="runtime",
                    actor_id=metadata["model_name"],
                ),
            )
            return plan_payload

        return await self._guard(operation())

    @activity.defn(name="agent.authorize_plan")
    async def authorize_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status in {RunStatus.PLANNING, RunStatus.REPLANNING}:
                await self._transition(payload, RunStatus.AUTHORIZED)
            return {"status": "authorized"}

        return await self._guard(operation())

    @activity.defn(name="agent.mark_executing")
    async def mark_executing(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status == RunStatus.AUTHORIZED:
                await self._transition(payload, RunStatus.EXECUTING)
            return {"status": "executing"}

        return await self._guard(operation())

    @activity.defn(name="agent.execute_task")
    async def execute_task(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_payload = payload.get("task", {})
        task_kind = (
            str(task_payload.get("kind", "unknown"))
            if isinstance(task_payload, dict)
            else "unknown"
        )
        task_model = "unknown"
        started = monotonic()
        status = "failed"

        async def operation() -> dict[str, Any]:
            nonlocal task_model
            activity.heartbeat(
                {
                    "phase": "starting",
                    "task_id": payload["task"]["id"],
                }
            )
            run = await self._run(payload)
            task = TaskSpec.model_validate(payload["task"])
            if task.id in run.outputs:
                return self._dump(run.outputs[task.id])
            dependencies = {
                key: WorkerOutput.model_validate(value)
                for key, value in payload.get("dependencies", {}).items()
            }
            attempt = self._activity_attempt(payload)
            metadata = self._runtime_audit_metadata(
                "worker",
                run,
                task=task,
                retry_count=attempt - 1,
            )
            task_model = str(metadata["model_name"])
            started_at = datetime.now(UTC)
            input_refs = [
                {
                    "kind": "artifact",
                    **reference.model_dump(mode="json"),
                }
                for reference in task.input_refs
            ]
            input_refs.extend(
                {
                    "kind": "task_output",
                    "task_id": dependency_id,
                    "output_hash": payload_hash(dependency.model_dump(mode="json")),
                }
                for dependency_id, dependency in sorted(dependencies.items())
            )
            execution = TaskExecutionRecord(
                task_execution_id=uuid5(
                    run.run_id,
                    (f"plan:{run.current_plan_version}:task:{task.id}:attempt:{attempt}"),
                ),
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                plan_version=run.current_plan_version,
                task_id=task.id,
                task_kind=task.kind,
                attempt=attempt,
                status="running",
                model_name=metadata["model_name"],
                model_settings=metadata["model_settings"],
                prompt_id=metadata["prompt_id"],
                prompt_version=metadata["prompt_version"],
                input_refs=input_refs,
                started_at=started_at,
                created_at=started_at,
            )
            await self._deps.store.audit.start_task(
                execution,
                AuditEvent(
                    event_type="task.started",
                    payload={
                        "task_execution_id": str(execution.task_execution_id),
                        "task_id": task.id,
                        "task_kind": task.kind,
                        "plan_version": run.current_plan_version,
                        "attempt": attempt,
                        "model_name": metadata["model_name"],
                        "model_settings": metadata["model_settings"],
                        "prompt_id": metadata["prompt_id"],
                        "prompt_version": metadata["prompt_version"],
                        "input_refs": input_refs,
                    },
                    correlation_id=str(payload["correlation_id"]),
                    actor_type="runtime",
                    actor_id=metadata["model_name"],
                    task_id=task.id,
                ),
            )
            try:
                output = await self._invoke_runtime(
                    payload,
                    run,
                    lambda context: self._deps.runtime.execute_task(
                        context,
                        task,
                        dependencies,
                    ),
                    role="worker",
                    task_id=task.id,
                )
            except Exception as exc:
                execution.status = "failed"
                execution.error_code = (
                    exc.code if isinstance(exc, PlatformError) else type(exc).__name__
                )
                execution.completed_at = datetime.now(UTC)
                await self._deps.store.audit.finish_task(
                    execution,
                    AuditEvent(
                        event_type="task.failed",
                        payload={
                            "task_execution_id": str(execution.task_execution_id),
                            "task_id": task.id,
                            "plan_version": execution.plan_version,
                            "attempt": attempt,
                            "error_code": execution.error_code,
                        },
                        correlation_id=str(payload["correlation_id"]),
                        actor_type="runtime",
                        actor_id=metadata["model_name"],
                        task_id=task.id,
                    ),
                )
                raise
            run = await self._run(payload)
            expected_version = run.version
            run.outputs[task.id] = output
            total = len(run.plan.tasks) if run.plan is not None else 1
            run.progress = len(run.outputs) / total
            run.updated_at = datetime.now(UTC)
            output_payload = self._dump(output)
            output_digest = payload_hash(output_payload)
            execution.status = "succeeded"
            execution.output_json = output_payload
            execution.output_artifact_id = (
                output.artifacts[0] if len(output.artifacts) == 1 else None
            )
            execution.completed_at = datetime.now(UTC)
            await self._deps.store.audit.complete_task_with_run(
                run,
                expected_version,
                execution,
                AuditEvent(
                    event_type="task.completed",
                    payload={
                        "task_execution_id": str(execution.task_execution_id),
                        "task_id": task.id,
                        "plan_version": run.current_plan_version,
                        "attempt": attempt,
                        "progress": run.progress,
                        "output_hash": output_digest,
                        "artifact_ids": [str(value) for value in output.artifacts],
                    },
                    correlation_id=str(payload["correlation_id"]),
                    actor_type="runtime",
                    actor_id=metadata["model_name"],
                    task_id=task.id,
                ),
            )
            activity.heartbeat({"phase": "completed", "task_id": task.id})
            return output_payload

        try:
            result = await self._guard(operation())
            status = "completed"
            return result
        finally:
            if self._deps.observability is not None:
                duration_seconds = monotonic() - started
                self._deps.observability.record_task(
                    kind=task_kind,
                    model=task_model,
                    status=status,
                    duration_seconds=duration_seconds,
                )

    @activity.defn(name="agent.verify_run")
    async def verify_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status == RunStatus.EXECUTING:
                run = await self._transition(payload, RunStatus.VERIFYING)
            plan = ExecutionPlan.model_validate(payload["plan"])
            outputs = {
                key: WorkerOutput.model_validate(value) for key, value in payload["outputs"].items()
            }
            report = await self._invoke_runtime(
                payload,
                run,
                lambda context: self._deps.runtime.verify(
                    context,
                    run.contract,
                    plan,
                    outputs,
                ),
                role="verifier",
                task_id="verifier",
            )
            run = await self._run(payload)
            if report.verdict != "pass" and self._deps.observability is not None:
                self._deps.observability.record_verification_failure(
                    verifier="model",
                    reason="RUN_VERIFICATION_REVISE",
                )
            await self._deps.store.runs.append_event(
                run,
                "run.verified",
                {
                    "verdict": report.verdict,
                    "plan_version": plan.plan_version,
                },
                str(payload["correlation_id"]),
            )
            return cast(dict[str, Any], report.model_dump(mode="json"))

        return await self._guard(operation())

    @activity.defn(name="agent.revise_plan")
    async def revise_plan(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            previous = ExecutionPlan.model_validate(payload["plan"])
            run = await self._run(payload)
            if run.plan is not None and run.current_plan_version > previous.plan_version:
                return cast(dict[str, Any], run.plan.model_dump(mode="json"))
            if run.status == RunStatus.VERIFYING:
                run = await self._transition(payload, RunStatus.REPLANNING)
            revised = await self._invoke_runtime(
                payload,
                run,
                lambda context: self._deps.runtime.plan(context, run.contract),
                role="planner",
                task_id="planner",
            )
            revised = revised.model_copy(
                update={
                    "plan_id": uuid4(),
                    "plan_version": previous.plan_version + 1,
                }
            )
            run = await self._run(payload)
            expected_version = run.version
            revised_payload = cast(dict[str, Any], revised.model_dump(mode="json"))
            revised_digest = payload_hash(revised_payload)
            metadata = self._runtime_audit_metadata("planner", run)
            run.plan = revised
            run.current_plan_version = revised.plan_version
            run.outputs = {}
            run.updated_at = datetime.now(UTC)
            saved, _ = await self._deps.store.audit.save_plan_with_run(
                run,
                expected_version,
                PlanExecutionRecord(
                    plan_id=revised.plan_id,
                    run_id=run.run_id,
                    tenant_id=run.tenant_id,
                    plan_version=revised.plan_version,
                    schema_version=revised.schema_version,
                    plan_json=revised_payload,
                    plan_hash=revised_digest,
                    planner_model=metadata["model_name"],
                    prompt_id=metadata["prompt_id"],
                    prompt_version=metadata["prompt_version"],
                ),
                AuditEvent(
                    event_type="plan.revised",
                    payload={
                        "plan_id": str(revised.plan_id),
                        "plan_version": revised.plan_version,
                        "previous_plan_version": previous.plan_version,
                        "plan_hash": revised_digest,
                        "model_name": metadata["model_name"],
                        "model_settings": metadata["model_settings"],
                        "prompt_id": metadata["prompt_id"],
                        "prompt_version": metadata["prompt_version"],
                        "repair_instructions": payload["report"].get("repair_instructions", []),
                    },
                    correlation_id=str(payload["correlation_id"]),
                    actor_type="runtime",
                    actor_id=metadata["model_name"],
                ),
            )
            if saved.status == RunStatus.REPLANNING:
                await self._transition(payload, RunStatus.AUTHORIZED)
            return cast(dict[str, Any], revised.model_dump(mode="json"))

        return await self._guard(operation())

    @activity.defn(name="agent.list_actions")
    async def list_actions(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        async def operation() -> list[dict[str, Any]]:
            actions = await self._deps.store.actions.list_for_run(
                UUID(str(payload["run_id"])),
                str(payload["tenant_id"]),
            )
            return [
                {
                    "action_id": str(action.action_id),
                    "status": action.status.value,
                    "expires_at": action.expires_at.isoformat(),
                }
                for action in actions
            ]

        return await self._guard(operation())

    @activity.defn(name="agent.mark_waiting_approval")
    async def mark_waiting_approval(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status in {
                RunStatus.VERIFYING,
                RunStatus.AUTHORIZED,
                RunStatus.EXECUTING,
            }:
                await self._transition(payload, RunStatus.WAITING_APPROVAL)
            return {"status": "waiting_approval"}

        return await self._guard(operation())

    @activity.defn(name="agent.expire_actions")
    async def expire_actions(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            actions = await self._deps.store.actions.list_for_run(
                UUID(str(payload["run_id"])),
                str(payload["tenant_id"]),
            )
            expired = 0
            tenant_id = str(payload["tenant_id"])
            statuses: dict[str, str] = {}
            for action in actions:
                if action.status != ActionStatus.PENDING_APPROVAL:
                    statuses[str(action.action_id)] = action.status.value
                    continue
                async with self._deps.store.actions.transaction(
                    action.action_id,
                    tenant_id,
                ) as transaction:
                    locked = transaction.action
                    if locked.status != ActionStatus.PENDING_APPROVAL:
                        statuses[str(locked.action_id)] = locked.status.value
                        continue
                    expired_at = datetime.now(UTC)
                    previous_status = locked.status.value
                    transaction.events.append(
                        AuditEvent(
                            event_type=RunEventType.ACTION_EXPIRED.value,
                            payload=action_expired_event_payload(
                                run_id=locked.run_id,
                                action_id=locked.action_id,
                                payload_digest=locked.payload_hash,
                                previous_status=previous_status,
                                scheduled_expires_at=locked.expires_at,
                                expired_at=expired_at,
                                reason="workflow_approval_timeout",
                            ),
                            correlation_id=str(
                                payload.get("correlation_id")
                                or f"workflow:{locked.run_id}:approval-timeout"
                            ),
                            actor_type="workflow",
                            actor_id="temporal",
                            action_id=locked.action_id,
                        )
                    )
                    locked.status = ActionStatus.EXPIRED
                    locked.failure_code = "ACTION_EXPIRED"
                    locked.updated_at = expired_at
                    expired += 1
                    statuses[str(locked.action_id)] = locked.status.value
            return {"expired": expired, "statuses": statuses}

        return await self._guard(operation())

    @activity.defn(name="agent.commit_action")
    async def commit_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status == RunStatus.WAITING_APPROVAL:
                run = await self._transition(payload, RunStatus.COMMITTING)
            elif run.status != RunStatus.COMMITTING:
                raise PlatformError(
                    "RUN_NOT_COMMITTABLE",
                    "External action commit requires a Run in waiting_approval or committing",
                    http_status=409,
                    context={
                        "run_id": str(run.run_id),
                        "status": run.status.value,
                        "allowed_statuses": [
                            RunStatus.WAITING_APPROVAL.value,
                            RunStatus.COMMITTING.value,
                        ],
                    },
                )
            receipt = await self._deps.commit_service.commit(
                tenant_id=str(payload["tenant_id"]),
                principal_id="commit-worker",
                principal_scopes=(self._deps.commit_scopes or run.contract.principal.scopes),
                action_id=UUID(str(payload["action_id"])),
                correlation_id=str(payload["correlation_id"]),
            )
            return self._dump(receipt)

        return await self._guard(operation())

    @activity.defn(name="transaction.reconcile_action")
    async def reconcile_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            scopes = self._require_recovery_scopes()
            try:
                await self._deps.commit_service.reconcile_unknown(
                    tenant_id=str(payload["tenant_id"]),
                    principal_id="commit-worker",
                    principal_scopes=scopes,
                    action_id=UUID(str(payload["action_id"])),
                    correlation_id=str(payload["correlation_id"]),
                )
            except Exception:
                await self._settle_recovery_run(
                    payload,
                    operation="reconcile",
                    action_status="failed",
                )
                raise
            action = await self._deps.store.actions.get(
                UUID(str(payload["action_id"])),
                str(payload["tenant_id"]),
            )
            await self._settle_recovery_run(
                payload,
                operation="reconcile",
                action_status=action.status.value,
            )
            return {
                "action_id": str(action.action_id),
                "action_status": action.status.value,
                "requested_by": str(payload["requested_by"]),
            }

        return await self._guard(operation())

    @activity.defn(name="transaction.compensate_action")
    async def compensate_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            scopes = self._require_recovery_scopes()
            await self._begin_compensation(payload)
            try:
                result = await self._deps.commit_service.compensate(
                    tenant_id=str(payload["tenant_id"]),
                    principal_id="commit-worker",
                    principal_scopes=scopes,
                    action_id=UUID(str(payload["action_id"])),
                    correlation_id=str(payload["correlation_id"]),
                    reason=str(payload["reason"]),
                )
            except Exception:
                await self._settle_recovery_run(
                    payload,
                    operation="compensate",
                    action_status="failed",
                )
                raise
            action = await self._deps.store.actions.get(
                UUID(str(payload["action_id"])),
                str(payload["tenant_id"]),
            )
            await self._settle_recovery_run(
                payload,
                operation="compensate",
                action_status=action.status.value,
            )
            return {
                "action_id": str(action.action_id),
                "action_status": action.status.value,
                "requested_by": str(payload["requested_by"]),
                "result": self._dump(result),
            }

        return await self._guard(operation())

    def _require_recovery_scopes(self) -> frozenset[str]:
        if not self._deps.commit_scopes:
            raise PlatformError(
                "COMMIT_SCOPES_NOT_CONFIGURED",
                "Transaction recovery requires worker-owned commit scopes",
            )
        return self._deps.commit_scopes

    async def _begin_compensation(self, payload: dict[str, Any]) -> None:
        run = await self._run(payload)
        if run.status in {
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.COMMITTING,
        }:
            await self._transition(
                payload,
                RunStatus.COMPENSATING,
                reason="ACTION_RECOVERY_COMPENSATION_STARTED",
            )

    async def _settle_recovery_run(
        self,
        payload: dict[str, Any],
        *,
        operation: str,
        action_status: str,
    ) -> None:
        run = await self._run(payload)
        if run.status in TERMINAL_RUN_STATUSES:
            return
        await self._transition(
            payload,
            RunStatus.FAILED,
            reason=(f"ACTION_RECOVERY_{operation.upper()}_{action_status.upper()}"),
        )

    @activity.defn(name="agent.finalize_run")
    async def finalize_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status == RunStatus.COMPLETED:
                return {"status": "completed"}
            report_payload = payload.get("report")
            verdict = report_payload.get("verdict") if isinstance(report_payload, dict) else None
            if verdict != "pass":
                raise PlatformError(
                    "FINALIZATION_REQUIRES_VERIFICATION_PASS",
                    "Final response can only be persisted after a clean verification pass",
                    context={"verdict": verdict},
                )
            VerificationReport.model_validate(report_payload)
            plan = ExecutionPlan.model_validate(payload["plan"])
            outputs = {
                key: WorkerOutput.model_validate(value) for key, value in payload["outputs"].items()
            }
            await self._store_final_response(run, plan, outputs)
            refreshed = await self._run(payload)
            if refreshed.status not in TERMINAL_RUN_STATUSES:
                await self._transition(payload, RunStatus.COMPLETED)
            return {"status": "completed"}

        return await self._guard(operation())

    @activity.defn(name="agent.cancel_run")
    async def cancel_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            if run.status not in TERMINAL_RUN_STATUSES:
                await self._transition(
                    payload,
                    RunStatus.CANCELLED,
                    reason=str(payload.get("reason", "RUN_CANCELLED")),
                )
            return {"status": "cancelled"}

        return await self._guard(operation())

    @activity.defn(name="agent.fail_run")
    async def fail_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            run = await self._run(payload)
            reason = str(payload.get("reason", "DEPENDENCY_FAILURE"))
            if run.status not in TERMINAL_RUN_STATUSES:
                await self._transition(payload, RunStatus.FAILED, reason=reason)
            return {"status": "failed", "reason": reason}

        return await self._guard(operation())

    async def _run(self, payload: dict[str, Any]) -> Any:
        return await self._deps.store.runs.get(
            UUID(str(payload["run_id"])),
            str(payload["tenant_id"]),
        )

    async def _transition(
        self,
        payload: dict[str, Any],
        target: RunStatus,
        *,
        reason: str = "WORKFLOW_PROGRESS",
    ) -> Any:
        return await self._deps.run_service.transition(
            UUID(str(payload["run_id"])),
            str(payload["tenant_id"]),
            target,
            str(payload["correlation_id"]),
            reason_code=reason,
        )

    def _runtime_audit_metadata(
        self,
        role: str,
        run: Any,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, Any]:
        provider = getattr(self._deps.runtime, "audit_metadata", None)
        if not callable(provider):
            raise PlatformError(
                "RUNTIME_AUDIT_METADATA_REQUIRED",
                "Runtime must expose immutable model and prompt provenance",
                context={"role": role},
            )
        metadata = provider(
            role,
            run.contract,
            task=task,
            retry_count=retry_count,
        )
        if not isinstance(metadata, dict):
            raise PlatformError(
                "RUNTIME_AUDIT_METADATA_INVALID",
                "Runtime audit metadata must be a mapping",
                context={"role": role},
            )
        required_text = ("model_name", "prompt_id", "prompt_version")
        if any(
            not isinstance(metadata.get(field), str) or not metadata[field]
            for field in required_text
        ) or not isinstance(metadata.get("model_settings"), dict):
            raise PlatformError(
                "RUNTIME_AUDIT_METADATA_INVALID",
                "Runtime audit metadata is missing model or prompt provenance",
                context={"role": role},
            )
        return cast(dict[str, Any], metadata)

    @staticmethod
    def _activity_attempt(payload: dict[str, Any]) -> int:
        try:
            return max(int(activity.info().attempt), 1)
        except RuntimeError:
            return max(int(payload.get("attempt", 1)), 1)

    def _runtime_context(
        self,
        run: Any,
        payload: dict[str, Any],
    ) -> RuntimeExecutionContext:
        elapsed_seconds = max(
            (datetime.now(UTC) - run.created_at).total_seconds(),
            0.0,
        )
        budget = BudgetLedger.for_runtime(
            max_cost_usd=run.contract.max_cost_usd,
            max_tool_calls=run.contract.max_tool_calls,
            remaining_seconds=max(
                float(run.contract.max_duration_seconds) - elapsed_seconds,
                0.0,
            ),
            cost_usd=run.cost_actual_usd,
            tool_calls=run.tool_call_count,
        )
        return RuntimeExecutionContext(
            run_id=run.run_id,
            contract=run.contract,
            correlation_id=str(payload["correlation_id"]),
            gateway=self._deps.gateway,
            artifact_store=self._deps.store.artifacts,
            budget=budget,
        )

    async def _invoke_runtime(
        self,
        payload: dict[str, Any],
        run: Any,
        operation: Callable[[RuntimeExecutionContext], Awaitable[T]],
        *,
        role: str,
        task_id: str,
    ) -> T:
        context = self._runtime_context(run, payload)
        trajectory: TrajectoryCheck | None = None
        guard = self._deps.trajectory_guard
        if guard is not None:
            data_scope = run.contract.data_scope.model_dump(mode="json")
            raw_retry = payload.get("retry_count", 0)
            retry_count = raw_retry if isinstance(raw_retry, int) else 0
            trajectory = await guard.preflight(
                run_id=run.run_id,
                tenant_id=run.tenant_id,
                candidate=TrajectoryCandidate(
                    boundary="model",
                    task_id=task_id,
                    plan_version=run.current_plan_version,
                    operation_name=f"activity.{role}",
                    args_hash=payload_hash(
                        {
                            "role": role,
                            "task_id": task_id,
                            "plan_version": run.current_plan_version,
                        }
                    ),
                    data_scope_hash=payload_hash(data_scope),
                    retry_count=retry_count,
                    principal_id=run.principal_id,
                    principal_scopes=run.contract.principal.scopes,
                    requested_data_scope=data_scope,
                ),
                correlation_id=str(payload["correlation_id"]),
                actor_type="temporal-activity",
                actor_id=run.principal_id,
            )
        try:
            result = await operation(context)
        except Exception as exc:
            if trajectory is not None and guard is not None:
                await guard.record_outcome(
                    trajectory,
                    status="failed",
                    error_code=str(getattr(exc, "code", type(exc).__name__)),
                )
            raise
        else:
            if trajectory is not None and guard is not None:
                await guard.record_outcome(
                    trajectory,
                    status="succeeded",
                )
            return result
        finally:
            if context.budget is not None:
                await self._persist_runtime_usage(payload, context.budget.usage)

    async def _persist_runtime_usage(
        self,
        payload: dict[str, Any],
        usage: RuntimeUsage,
    ) -> None:
        if usage.is_empty:
            return
        for attempt in range(3):
            run = await self._run(payload)
            before = self._budget_utilization(
                cost_usd=run.cost_actual_usd,
                max_cost_usd=run.contract.max_cost_usd,
                tool_calls=run.tool_call_count,
                max_tool_calls=run.contract.max_tool_calls,
            )
            expected_version = run.version
            run.cost_actual_usd += usage.cost_usd
            run.token_input += usage.input_tokens
            run.token_output += usage.output_tokens
            run.tool_call_count += usage.tool_calls
            run.updated_at = datetime.now(UTC)
            after = self._budget_utilization(
                cost_usd=run.cost_actual_usd,
                max_cost_usd=run.contract.max_cost_usd,
                tool_calls=run.tool_call_count,
                max_tool_calls=run.contract.max_tool_calls,
            )
            warning = before < Decimal("0.8") <= after
            try:
                if warning:
                    event_payload = {
                        "utilization": self._decimal_string(after),
                        "cost_actual_usd": str(run.cost_actual_usd),
                        "max_cost_usd": str(run.contract.max_cost_usd),
                        "tool_call_count": run.tool_call_count,
                        "max_tool_calls": run.contract.max_tool_calls,
                        "token_input": run.token_input,
                        "token_output": run.token_output,
                        "pricing_catalog_version": usage.pricing_catalog_version,
                    }
                    atomic_save = getattr(
                        self._deps.store.runs,
                        "save_with_event",
                        None,
                    )
                    if callable(atomic_save):
                        await atomic_save(
                            run,
                            expected_version,
                            "budget.warning",
                            event_payload,
                            str(payload["correlation_id"]),
                        )
                    else:
                        saved = await self._deps.store.runs.save(run, expected_version)
                        await self._deps.store.runs.append_event(
                            saved,
                            "budget.warning",
                            event_payload,
                            str(payload["correlation_id"]),
                        )
                else:
                    await self._deps.store.runs.save(run, expected_version)
                return
            except PlatformError as exc:
                if exc.code != "OPTIMISTIC_LOCK_CONFLICT" or attempt == 2:
                    raise

    @staticmethod
    def _budget_utilization(
        *,
        cost_usd: Decimal,
        max_cost_usd: Decimal,
        tool_calls: int,
        max_tool_calls: int,
    ) -> Decimal:
        cost_utilization = cost_usd / max_cost_usd
        tool_utilization = (
            Decimal(tool_calls) / Decimal(max_tool_calls)
            if max_tool_calls > 0
            else (Decimal("1") if tool_calls > 0 else Decimal("0"))
        )
        return max(cost_utilization, tool_utilization)

    @staticmethod
    def _decimal_string(value: Decimal) -> str:
        return format(value.normalize(), "f")

    async def _store_final_response(
        self,
        run: Any,
        plan: ExecutionPlan,
        outputs: dict[str, WorkerOutput],
    ) -> None:
        synthesis = outputs.get("synthesize_report", outputs[plan.final_task_id])
        artifact_refs: list[ArtifactRef] = []
        for artifact_id in synthesis.artifacts:
            artifact_store = self._deps.store.artifacts
            get_metadata = getattr(artifact_store, "get_metadata", None)
            artifact = (
                await get_metadata(artifact_id, run.tenant_id)
                if callable(get_metadata)
                else await artifact_store.get(artifact_id, run.tenant_id)
            )
            artifact_refs.append(
                ArtifactRef(
                    artifact_id=artifact.artifact_id,
                    sha256=artifact.sha256,
                    classification=DataClassification(artifact.classification),
                    kind=artifact.kind,
                    media_type=artifact.media_type,
                    size_bytes=artifact.size_bytes,
                )
            )
        receipts: list[CommitReceipt] = []
        actions = await self._deps.store.actions.list_for_run(
            run.run_id,
            run.tenant_id,
        )
        for action in actions:
            if action.status != ActionStatus.COMMITTED or not action.receipt:
                continue
            verification = action.verification
            receipts.append(
                CommitReceipt(
                    external_operation_id=action.receipt.get("external_operation_id"),
                    committed_at=datetime.fromisoformat(action.receipt["committed_at"]),
                    result_summary=action.receipt.get("result_summary", {}),
                    idempotency_key=action.idempotency_key,
                    verification=VerificationResult(
                        passed=bool(verification["passed"]),
                        verified_at=datetime.fromisoformat(verification["verified_at"]),
                        method=verification["method"],
                        details=verification.get("details", {}),
                    ),
                )
            )
        criterion_verifications = aggregate_final_criterion_verifications(
            run.contract,
            outputs,
            synthesis,
        )
        finalized_output = synthesis.model_copy(
            update={"criterion_verifications": criterion_verifications}
        )
        findings = deterministic_verification_findings(
            run.contract,
            {plan.final_task_id: finalized_output},
        )
        if findings["hard_failures"]:
            raise PlatformError(
                "FINAL_RESPONSE_CRITERION_COVERAGE_INCOMPLETE",
                "Final response is missing a passed, observable must criterion check",
                context={
                    "failed_criteria": findings["failed_criteria"],
                    "hard_failures": findings["hard_failures"],
                },
            )
        result = FinalResponse(
            summary=synthesis.summary,
            claims=synthesis.claims,
            evidence=synthesis.evidence,
            criterion_verifications=criterion_verifications,
            artifacts=artifact_refs,
            receipts=receipts,
            caveats=synthesis.uncertainties,
        )
        expected_version = run.version
        run.result = result
        run.updated_at = datetime.now(UTC)
        await self._deps.store.runs.save(run, expected_version)

    @staticmethod
    async def _guard(awaitable: Awaitable[T]) -> T:
        try:
            return await awaitable
        except PlatformError as exc:
            raise ApplicationError(
                str(exc),
                exc.context,
                type=exc.code,
                non_retryable=not exc.retryable,
            ) from exc

    @staticmethod
    def _dump(value: Any) -> dict[str, Any]:
        if hasattr(value, "model_dump"):
            return cast(dict[str, Any], value.model_dump(mode="json"))
        if isinstance(value, dict):
            return value
        return {"value": value}
