from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, cast
from uuid import UUID, uuid5

from agent_platform.agents.deterministic_runtime import RuntimeExecutionContext
from agent_platform.agents.verification import (
    aggregate_final_criterion_verifications,
    deterministic_verification_findings,
)
from agent_platform.application.dag_scheduler import (
    BudgetLedger,
    CancellationToken,
    DagScheduler,
    SchedulerContext,
)
from agent_platform.application.errors import PlatformError
from agent_platform.application.records import (
    AuditEvent,
    PlanExecutionRecord,
    TaskExecutionRecord,
)
from agent_platform.domain.enums import ActionStatus, DataClassification, RunStatus
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    ArtifactRef,
    CommitReceipt,
    FinalResponse,
    VerificationResult,
)


class _Checkpoint:
    def __init__(
        self,
        workflow: InlineWorkflowStarter,
        run_id: UUID,
        tenant_id: str,
    ) -> None:
        self._workflow = workflow
        self._run_id = run_id
        self._tenant_id = tenant_id
        self._executions: dict[str, TaskExecutionRecord] = {}

    async def task_started(self, task: Any, dependencies: dict[str, Any]) -> None:
        run = await self._workflow.store.runs.get(self._run_id, self._tenant_id)
        metadata = self._workflow._runtime_audit_metadata(
            "worker",
            run,
            task=task,
        )
        started_at = datetime.now(UTC)
        input_refs = [
            {"kind": "artifact", **reference.model_dump(mode="json")}
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
                f"plan:{run.current_plan_version}:task:{task.id}:attempt:1",
            ),
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            plan_version=run.current_plan_version,
            task_id=task.id,
            task_kind=task.kind,
            attempt=1,
            status="running",
            model_name=metadata["model_name"],
            model_settings=metadata["model_settings"],
            prompt_id=metadata["prompt_id"],
            prompt_version=metadata["prompt_version"],
            input_refs=input_refs,
            started_at=started_at,
            created_at=started_at,
        )
        self._executions[task.id] = execution
        await self._workflow.store.audit.start_task(
            execution,
            AuditEvent(
                event_type="task.started",
                payload={
                    "task_execution_id": str(execution.task_execution_id),
                    "task_id": task.id,
                    "task_kind": task.kind,
                    "plan_version": run.current_plan_version,
                    "attempt": 1,
                    "model_name": metadata["model_name"],
                    "model_settings": metadata["model_settings"],
                    "prompt_id": metadata["prompt_id"],
                    "prompt_version": metadata["prompt_version"],
                    "input_refs": input_refs,
                },
                correlation_id=self._workflow._correlation_ids[self._run_id],
                actor_type="runtime",
                actor_id=metadata["model_name"],
                task_id=task.id,
            ),
        )

    async def task_failed(self, task: Any, error: Exception) -> None:
        execution = self._executions.get(task.id)
        if execution is None:
            return
        execution.status = "failed"
        execution.error_code = (
            error.code if isinstance(error, PlatformError) else type(error).__name__
        )
        execution.completed_at = datetime.now(UTC)
        await self._workflow.store.audit.finish_task(
            execution,
            AuditEvent(
                event_type="task.failed",
                payload={
                    "task_execution_id": str(execution.task_execution_id),
                    "task_id": task.id,
                    "plan_version": execution.plan_version,
                    "attempt": execution.attempt,
                    "error_code": execution.error_code,
                },
                correlation_id=self._workflow._correlation_ids[self._run_id],
                actor_type="runtime",
                actor_id=execution.model_name,
                task_id=task.id,
            ),
        )

    async def task_completed(self, task_id: str, output: Any) -> None:
        execution = self._executions[task_id]
        run = await self._workflow.store.runs.get(self._run_id, self._tenant_id)
        expected_version = run.version
        run.outputs[task_id] = output
        total = len(run.plan.tasks) if run.plan is not None else 1
        run.progress = len(run.outputs) / total
        run.tool_call_count += 1
        run.updated_at = datetime.now(UTC)
        output_payload = output.model_dump(mode="json")
        execution.status = "succeeded"
        execution.output_json = output_payload
        execution.output_artifact_id = (
            output.artifacts[0] if len(output.artifacts) == 1 else None
        )
        execution.completed_at = datetime.now(UTC)
        await self._workflow.store.audit.complete_task_with_run(
            run,
            expected_version,
            execution,
            AuditEvent(
                event_type="task.completed",
                payload={
                    "task_execution_id": str(execution.task_execution_id),
                    "task_id": task_id,
                    "plan_version": run.current_plan_version,
                    "progress": run.progress,
                    "output_hash": payload_hash(output_payload),
                    "artifact_ids": [str(value) for value in output.artifacts],
                },
                correlation_id=self._workflow._correlation_ids[self._run_id],
                actor_type="runtime",
                actor_id=execution.model_name,
                task_id=task_id,
            ),
        )

class InlineWorkflowStarter:
    """Local durable-contract runner; production uses Temporal."""

    def __init__(
        self,
        *,
        store: Any,
        runtime: Any,
        gateway: Any,
        commit_service: Any,
    ) -> None:
        self.store = store
        self._runtime = runtime
        self._gateway = gateway
        self._commit_service = commit_service
        self._run_service: Any | None = None
        self._tasks: dict[UUID, asyncio.Task[None]] = {}
        self._tokens: dict[UUID, CancellationToken] = {}
        self._resume_events: dict[UUID, asyncio.Event] = {}
        self._action_events: dict[UUID, asyncio.Event] = {}
        self._correlation_ids: dict[UUID, str] = {}

    def bind(self, run_service: Any) -> None:
        self._run_service = run_service

    async def start(
        self,
        run_id: UUID,
        tenant_id: str,
        correlation_id: str,
        *,
        contract: Any | None = None,
    ) -> None:
        del contract
        if self._run_service is None:
            raise RuntimeError("INLINE_WORKFLOW_NOT_BOUND")
        if run_id in self._tasks:
            return
        self._tokens[run_id] = CancellationToken()
        resume = asyncio.Event()
        resume.set()
        self._resume_events[run_id] = resume
        self._action_events[run_id] = asyncio.Event()
        self._correlation_ids[run_id] = correlation_id
        self._tasks[run_id] = asyncio.create_task(
            self._execute(run_id, tenant_id),
            name=f"inline-agent-run-{run_id}",
        )

    async def cancel(self, run_id: UUID, tenant_id: str, reason: str) -> None:
        del tenant_id
        token = self._tokens.get(run_id)
        if token is not None:
            token.cancel(reason)
        self._resume_events.get(run_id, asyncio.Event()).set()
        self._action_events.get(run_id, asyncio.Event()).set()

    async def pause(self, run_id: UUID, tenant_id: str, reason: str) -> None:
        del tenant_id, reason
        event = self._resume_events.get(run_id)
        if event is not None:
            event.clear()

    async def resume(self, run_id: UUID, tenant_id: str) -> None:
        del tenant_id
        event = self._resume_events.get(run_id)
        if event is not None:
            event.set()

    async def notify_action(
        self,
        action_id: UUID,
        tenant_id: str,
        decision: str,
    ) -> None:
        del decision
        for run_id in self._action_events:
            actions = await self.store.actions.list_for_run(run_id, tenant_id)
            if any(action.action_id == action_id for action in actions):
                self._action_events[run_id].set()
                return

    def _runtime_audit_metadata(
        self,
        role: str,
        run: Any,
        *,
        task: Any | None = None,
    ) -> dict[str, Any]:
        provider = getattr(self._runtime, "audit_metadata", None)
        if not callable(provider):
            raise PlatformError(
                "RUNTIME_AUDIT_METADATA_REQUIRED",
                "Runtime must expose immutable model and prompt provenance",
                context={"role": role},
            )
        metadata = provider(role, run.contract, task=task, retry_count=0)
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
    def _tenant(self, run_id: UUID) -> str:
        task = self._tasks.get(run_id)
        if task is None:
            raise KeyError(run_id)
        # The run task name is not authority; tenant is read from the store below.
        for run in self.store.runs._runs.values():
            if run.run_id == run_id:
                return cast(str, run.tenant_id)
        raise KeyError(run_id)

    async def wait_until_terminal(
        self,
        run_id: UUID,
        *,
        timeout_seconds: float,
    ) -> Any:
        task = self._tasks[run_id]
        async with asyncio.timeout(timeout_seconds):
            await asyncio.shield(task)
        return await self.store.runs.get(run_id, self._tenant(run_id))

    async def _await_control(self, run_id: UUID) -> None:
        self._tokens[run_id].raise_if_cancelled()
        await self._resume_events[run_id].wait()
        self._tokens[run_id].raise_if_cancelled()

    async def _execute(self, run_id: UUID, tenant_id: str) -> None:
        assert self._run_service is not None
        correlation_id = self._correlation_ids[run_id]
        try:
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.CLASSIFIED, correlation_id
            )
            await self._await_control(run_id)
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.PLANNING, correlation_id
            )
            run = await self.store.runs.get(run_id, tenant_id)
            runtime_context = RuntimeExecutionContext(
                run_id=run_id,
                contract=run.contract,
                correlation_id=correlation_id,
                gateway=self._gateway,
                artifact_store=self.store.artifacts,
            )
            plan = await self._runtime.plan(runtime_context, run.contract)
            expected_version = run.version
            plan_json = plan.model_dump(mode="json")
            plan_digest = payload_hash(plan_json)
            metadata = self._runtime_audit_metadata("planner", run)
            run.plan = plan
            run.current_plan_version = plan.plan_version
            run.updated_at = datetime.now(UTC)
            run, _ = await self.store.audit.save_plan_with_run(
                run,
                expected_version,
                PlanExecutionRecord(
                    plan_id=plan.plan_id,
                    run_id=run.run_id,
                    tenant_id=run.tenant_id,
                    plan_version=plan.plan_version,
                    schema_version=plan.schema_version,
                    plan_json=plan_json,
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
                    correlation_id=correlation_id,
                    actor_type="runtime",
                    actor_id=metadata["model_name"],
                ),
            )
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.AUTHORIZED, correlation_id
            )
            await self._await_control(run_id)
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.EXECUTING, correlation_id
            )
            loop = asyncio.get_running_loop()
            scheduler_context = SchedulerContext(
                contract=run.contract,
                budget=BudgetLedger(
                    max_cost_usd=run.contract.max_cost_usd,
                    max_tool_calls=run.contract.max_tool_calls,
                    deadline_monotonic=loop.time() + run.contract.max_duration_seconds,
                ),
                cancel_token=self._tokens[run_id],
                checkpoint=_Checkpoint(self, run_id, tenant_id),
                runtime_context=runtime_context,
            )
            outputs = await DagScheduler(self._runtime).execute(scheduler_context, plan)
            await self._await_control(run_id)
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.VERIFYING, correlation_id
            )
            report = await self._runtime.verify(runtime_context, run.contract, plan, outputs)
            if report.verdict != "pass":
                await self._run_service.transition(
                    run_id,
                    tenant_id,
                    RunStatus.FAILED,
                    correlation_id,
                    reason_code="VERIFICATION_FAILED",
                )
                return
            actions = list(await self.store.actions.list_for_run(run_id, tenant_id))
            if actions:
                await self._run_service.transition(
                    run_id,
                    tenant_id,
                    RunStatus.WAITING_APPROVAL,
                    correlation_id,
                )
                await self._wait_for_actions(run_id, tenant_id, actions)
                await self._await_control(run_id)
                actions = list(await self.store.actions.list_for_run(run_id, tenant_id))
                if any(action.status != ActionStatus.APPROVED for action in actions):
                    await self._run_service.transition(
                        run_id,
                        tenant_id,
                        RunStatus.FAILED,
                        correlation_id,
                        reason_code="ACTION_NOT_APPROVED",
                    )
                    return
                await self._run_service.transition(
                    run_id, tenant_id, RunStatus.COMMITTING, correlation_id
                )
                for action in actions:
                    await self._commit_service.commit(
                        tenant_id=tenant_id,
                        principal_id="commit-worker",
                        principal_scopes=frozenset({"email:prepare"}),
                        action_id=action.action_id,
                        correlation_id=correlation_id,
                    )
            await self._finalize(run_id, tenant_id, plan, outputs)
            await self._run_service.transition(
                run_id, tenant_id, RunStatus.COMPLETED, correlation_id
            )
        except PlatformError as exc:
            await self._fail_or_cancel(run_id, tenant_id, exc.code)
        except Exception:
            await self._fail_or_cancel(run_id, tenant_id, "DEPENDENCY_FAILURE")
            raise

    async def _wait_for_actions(self, run_id: UUID, tenant_id: str, actions: list[Any]) -> None:
        event = self._action_events[run_id]
        while True:
            self._tokens[run_id].raise_if_cancelled()
            current = list(await self.store.actions.list_for_run(run_id, tenant_id))
            if all(
                action.status
                in {
                    ActionStatus.APPROVED,
                    ActionStatus.REJECTED,
                    ActionStatus.EXPIRED,
                    ActionStatus.CANCELLED,
                }
                for action in current
            ):
                return
            seconds = min(
                max((action.expires_at - datetime.now(UTC)).total_seconds(), 0.01)
                for action in actions
            )
            event.clear()
            try:
                await asyncio.wait_for(event.wait(), timeout=seconds)
            except TimeoutError:
                for current_action in current:
                    if current_action.status == ActionStatus.PENDING_APPROVAL:
                        async with self.store.actions.get_for_update(
                            current_action.action_id, tenant_id
                        ) as locked:
                            locked.status = ActionStatus.EXPIRED
                return

    async def _finalize(
        self,
        run_id: UUID,
        tenant_id: str,
        plan: Any,
        outputs: dict[str, Any],
    ) -> None:
        synthesis = outputs.get("synthesize_report", outputs[plan.final_task_id])
        artifact_refs: list[ArtifactRef] = []
        for artifact_id in synthesis.artifacts:
            artifact_store = self.store.artifacts
            get_metadata = getattr(artifact_store, "get_metadata", None)
            artifact = (
                await get_metadata(artifact_id, tenant_id)
                if callable(get_metadata)
                else await artifact_store.get(artifact_id, tenant_id)
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
        for action in await self.store.actions.list_for_run(run_id, tenant_id):
            if action.status == ActionStatus.COMMITTED and action.receipt:
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
        run = await self.store.runs.get(run_id, tenant_id)
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
        run.cost_actual_usd = sum((task.estimated_cost_usd for task in plan.tasks), Decimal("0"))
        run.updated_at = datetime.now(UTC)
        await self.store.runs.save(run, expected_version)

    async def _fail_or_cancel(self, run_id: UUID, tenant_id: str, reason_code: str) -> None:
        assert self._run_service is not None
        run = await self.store.runs.get(run_id, tenant_id)
        if run.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}:
            return
        target = (
            RunStatus.CANCELLED
            if reason_code == "RUN_CANCELLED" or run.cancellation_requested
            else RunStatus.FAILED
        )
        await self._run_service.transition(
            run_id,
            tenant_id,
            target,
            self._correlation_ids[run_id],
            reason_code=reason_code,
        )
