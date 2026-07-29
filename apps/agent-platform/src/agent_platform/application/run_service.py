from __future__ import annotations

from collections.abc import Awaitable, Mapping
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from agent_platform.api.schemas import CreateRunRequest
from agent_platform.application.errors import Conflict, PlatformError, WorkflowSignalFailed
from agent_platform.application.records import RunRecord
from agent_platform.domain.enums import ActionStatus, RiskLevel, RunStatus
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    DataScope,
    OutputContract,
    Principal,
    SuccessCriterion,
    TaskContract,
)
from agent_platform.domain.state_machines import ensure_run_transition
from agent_platform.infrastructure.capacity_cost import RunPriority
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


class RunService:
    def __init__(
        self,
        runs: Any,
        actions: Any,
        workflow: Any,
        *,
        capabilities: Any | None = None,
        kill_switches: Any | None = None,
        observability: RuntimeObservability | None = None,
        capacity_cost: Any | None = None,
    ) -> None:
        self._runs = runs
        self._actions = actions
        self._workflow = workflow
        self._capabilities = capabilities
        self._kill_switches = kill_switches
        self._observability = observability
        self._capacity_cost = capacity_cost

    async def create(
        self,
        request: CreateRunRequest,
        principal: Principal,
        data_scope: DataScope,
        *,
        idempotency_key: str,
        correlation_id: str,
    ) -> tuple[RunRecord, bool]:
        self._validate_capability_scope(request, principal, data_scope)
        await self._require_capabilities_enabled(
            principal.tenant_id, frozenset(request.allowed_capabilities)
        )
        await self._require_execution_allowed(
            tenant_id=principal.tenant_id,
            use_case=self._request_use_case(request),
            capabilities=frozenset(request.allowed_capabilities),
            operation="execute",
        )
        capacity_decision = None
        if self._capacity_cost is not None:
            capacity_decision = await self._capacity_cost.admit_run(
                tenant_id=principal.tenant_id,
                idempotency_key=idempotency_key,
                requested_cost_usd=request.budget.max_cost_usd,
                max_duration_seconds=request.budget.max_duration_seconds,
                priority=self._priority(request),
            )
        contract_constraints = dict(request.constraints)
        if capacity_decision is not None:
            contract_constraints["_platform_budget_control"] = (
                capacity_decision.budget_control_level.value
            )
        contract = TaskContract(
            goal=request.goal,
            success_criteria=[
                SuccessCriterion(
                    id=item.id,
                    description=item.description,
                    severity=item.severity,
                    verification=item.verification,
                    evidence_required=(item.verification == "evidence" or item.severity == "must"),
                )
                for item in request.success_criteria
            ],
            principal=principal,
            data_scope=data_scope,
            risk=self._risk(request),
            allowed_capabilities=frozenset(request.allowed_capabilities),
            constraints=contract_constraints,
            max_cost_usd=request.budget.max_cost_usd,
            max_duration_seconds=request.budget.max_duration_seconds,
            max_tool_calls=request.budget.max_tool_calls,
            max_parallelism=min(max(len(request.allowed_capabilities), 1), 3),
            max_replans=2,
            external_write_policy=request.external_write_policy,
            requested_output=OutputContract(
                schema_name=request.requested_output.format,
                media_type="application/json",
                artifact_required="report" in request.requested_output.format,
            ),
        )
        serialized_request = request.model_dump(mode="json")
        request_digest = payload_hash(serialized_request)
        run_id = uuid4()
        run = RunRecord(
            run_id=run_id,
            tenant_id=principal.tenant_id,
            principal_id=principal.user_id,
            contract=contract,
            idempotency_key=idempotency_key,
            request_hash=request_digest,
            workflow_id=f"agent-run-{run_id}",
        )
        try:
            stored, created, retry_workflow_start = await self._create_and_append_event(
                run,
                "run.status_changed",
                {
                    "from": None,
                    "to": RunStatus.RECEIVED.value,
                    "at": run.created_at.isoformat(),
                    "reason_code": "RUN_ACCEPTED",
                },
                correlation_id,
            )
        except Exception as exc:
            if (
                capacity_decision is not None
                and capacity_decision.newly_reserved
                and self._capacity_cost is not None
            ):
                await self._capacity_cost.release_if_unbound(
                    tenant_id=principal.tenant_id,
                    idempotency_key=idempotency_key,
                )
            if self._observability is not None and (
                not isinstance(exc, PlatformError) or exc.http_status >= 500
            ):
                self._observability.record_run_accept(outcome="unavailable")
            raise
        if self._observability is not None:
            self._observability.record_run_accept(outcome="accepted")
        if self._capacity_cost is not None and stored.status not in {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }:
            await self._capacity_cost.bind_run(
                tenant_id=stored.tenant_id,
                idempotency_key=stored.idempotency_key,
                run_id=stored.run_id,
            )
        if created and self._observability is not None:
            use_case = self._contract_use_case(stored.contract)
            tenant_tier = self._contract_tenant_tier(stored.contract)
            with self._observability.span(
                "agent.run.accept",
                {
                    "correlation_id": correlation_id,
                    "run_id": str(stored.run_id),
                    "workflow_id": stored.workflow_id,
                    "tenant_id_hash": self._observability.tenant_hash(stored.tenant_id),
                    "use_case": use_case,
                    "tenant_tier": tenant_tier,
                    "risk": stored.contract.risk.value,
                    "status": RunStatus.RECEIVED.value,
                },
            ):
                self._observability.record_run_received(
                    use_case=use_case,
                    risk=stored.contract.risk.value,
                    tenant_tier=tenant_tier,
                )
        if created or retry_workflow_start:
            if self._observability is None:
                await self._workflow.start(
                    stored.run_id,
                    stored.tenant_id,
                    correlation_id,
                    contract=stored.contract,
                )
            else:
                with self._observability.span(
                    "agent.workflow.start",
                    {
                        "correlation_id": correlation_id,
                        "run_id": str(stored.run_id),
                        "workflow_id": stored.workflow_id,
                        "tenant_id_hash": self._observability.tenant_hash(stored.tenant_id),
                        "use_case": self._contract_use_case(stored.contract),
                        "tenant_tier": self._contract_tenant_tier(stored.contract),
                    },
                ):
                    await self._workflow.start(
                        stored.run_id,
                        stored.tenant_id,
                        correlation_id,
                        contract=stored.contract,
                    )
        return stored, created

    async def get(self, run_id: UUID, principal: Principal) -> RunRecord:
        return cast(
            RunRecord,
            await self._runs.get(run_id, principal.tenant_id),
        )

    async def transition(
        self,
        run_id: UUID,
        tenant_id: str,
        target: RunStatus,
        correlation_id: str,
        *,
        reason_code: str = "WORKFLOW_PROGRESS",
        expected: set[RunStatus] | None = None,
    ) -> RunRecord:
        run = await self._runs.get(run_id, tenant_id)
        controlled_operation = {
            RunStatus.PLANNING: "model",
            RunStatus.REPLANNING: "model",
            RunStatus.EXECUTING: "execute",
            RunStatus.VERIFYING: "model",
            RunStatus.COMMITTING: "commit",
        }.get(target)
        if controlled_operation is not None:
            await self._require_execution_allowed(
                tenant_id=tenant_id,
                use_case=self._contract_use_case(run.contract),
                capabilities=run.contract.allowed_capabilities,
                operation=controlled_operation,
            )
        if expected is not None and run.status not in expected:
            raise Conflict(
                "INVALID_STATE_TRANSITION",
                "Run is not in an expected source state",
                run_id=str(run_id),
                current=run.status.value,
                expected=sorted(item.value for item in expected),
            )
        ensure_run_transition(run.status, target, run_id=str(run_id))
        previous = run.status
        expected_version = run.version
        if target == RunStatus.PAUSED:
            run.paused_from = previous
        elif previous == RunStatus.PAUSED:
            run.paused_from = None
            run.pause_requested = False
        run.status = target
        run.updated_at = datetime.now(UTC)
        if target in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}:
            run.completed_at = run.updated_at
            if target == RunStatus.COMPLETED:
                run.progress = 1.0
        settlement = None
        if (
            target in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}
            and self._capacity_cost is not None
        ):
            settlement = await self._capacity_cost.settle_run(run)
            if target is RunStatus.COMPLETED and (
                settlement.run_limit_exceeded
                or settlement.tenant_daily_limit_exceeded
                or settlement.tenant_monthly_limit_exceeded
            ):
                raise PlatformError(
                    "BUDGET_EXHAUSTED",
                    "Full platform cost exceeds an approved Run or tenant budget",
                    http_status=409,
                    context={
                        "run_id": str(run.run_id),
                        "total_cost_usd": str(settlement.breakdown.total_usd),
                        "run_limit_usd": str(run.contract.max_cost_usd),
                        "tenant_daily_utilization": str(settlement.daily_utilization),
                        "tenant_monthly_utilization": str(settlement.monthly_utilization),
                    },
                )
        transition_payload: dict[str, Any] = {
            "from": previous.value,
            "to": target.value,
            "at": run.updated_at.isoformat(),
            "reason_code": reason_code,
        }
        if settlement is not None:
            transition_payload["cost_reconciliation"] = settlement.breakdown.model_dump(mode="json")
        saved = await self._save_and_append_event(
            run,
            expected_version,
            (
                f"run.{target.value}"
                if target in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}
                else "run.status_changed"
            ),
            transition_payload,
            correlation_id,
        )
        if self._observability is not None and target in {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }:
            use_case = self._contract_use_case(saved.contract)
            tenant_tier = self._contract_tenant_tier(saved.contract)
            if settlement is not None:
                self._observability.record_cost_settlement(
                    components=settlement.breakdown.components,
                    daily_utilization=settlement.daily_utilization,
                    monthly_utilization=settlement.monthly_utilization,
                    control_level=settlement.budget_control_level.value,
                    use_case=use_case,
                    tenant_tier=tenant_tier,
                    succeeded=target is RunStatus.COMPLETED,
                )
            duration_seconds = max(
                (saved.updated_at - saved.created_at).total_seconds(),
                0.0,
            )
            with self._observability.span(
                "agent.run.terminal",
                {
                    "correlation_id": correlation_id,
                    "run_id": str(saved.run_id),
                    "workflow_id": saved.workflow_id,
                    "plan_version": saved.current_plan_version,
                    "tenant_id_hash": self._observability.tenant_hash(saved.tenant_id),
                    "use_case": use_case,
                    "risk": saved.contract.risk.value,
                    "status": target.value,
                },
            ):
                self._observability.record_run_terminal(
                    use_case=use_case,
                    risk=saved.contract.risk.value,
                    status=target.value,
                    duration_seconds=duration_seconds,
                    cost_usd=(
                        settlement.breakdown.total_usd
                        if settlement is not None
                        else saved.cost_actual_usd
                    ),
                    cost_budget_usd=saved.contract.max_cost_usd,
                    tool_calls=saved.tool_call_count,
                    tool_call_budget=saved.contract.max_tool_calls,
                    duration_budget_seconds=saved.contract.max_duration_seconds,
                    tenant_tier=tenant_tier,
                    model="unknown",
                )
        return saved

    async def pause(
        self,
        run_id: UUID,
        principal: Principal,
        reason: str,
        correlation_id: str,
    ) -> RunRecord:
        current = cast(
            RunRecord,
            await self._runs.get(run_id, principal.tenant_id),
        )
        paused = (
            current
            if current.status == RunStatus.PAUSED
            else await self.transition(
                run_id,
                principal.tenant_id,
                RunStatus.PAUSED,
                correlation_id,
                reason_code="USER_PAUSE",
            )
        )
        await self._signal_workflow(
            run_id,
            "pause",
            self._workflow.pause(run_id, principal.tenant_id, reason),
        )
        return paused

    async def resume(
        self,
        run_id: UUID,
        principal: Principal,
        correlation_id: str,
    ) -> RunRecord:
        paused = cast(
            RunRecord,
            await self._runs.get(run_id, principal.tenant_id),
        )
        if paused.status == RunStatus.PAUSED and paused.paused_from is not None:
            resumed = await self.transition(
                run_id,
                principal.tenant_id,
                paused.paused_from,
                correlation_id,
                expected={RunStatus.PAUSED},
                reason_code="USER_RESUME",
            )
        elif (
            paused.status
            in {
                RunStatus.COMPLETED,
                RunStatus.FAILED,
                RunStatus.CANCELLED,
            }
            or paused.cancellation_requested
        ):
            raise Conflict(
                "INVALID_STATE_TRANSITION",
                "Run does not have a persisted pause origin",
                run_id=str(run_id),
            )
        else:
            # A retry after the state transition must re-send a lost signal.
            resumed = paused
        await self._signal_workflow(
            run_id,
            "resume",
            self._workflow.resume(run_id, principal.tenant_id),
        )
        return resumed

    async def cancel(
        self,
        run_id: UUID,
        principal: Principal,
        reason: str,
        correlation_id: str,
    ) -> RunRecord:
        run = cast(
            RunRecord,
            await self._runs.get(run_id, principal.tenant_id),
        )
        if run.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}:
            return run
        if not run.cancellation_requested:
            expected_version = run.version
            run.cancellation_requested = True
            run.updated_at = datetime.now(UTC)
            run = await self._save_and_append_event(
                run,
                expected_version,
                "run.cancellation_requested",
                {"reason": reason},
                correlation_id,
            )
        await self._signal_workflow(
            run_id,
            "cancel",
            self._workflow.cancel(run_id, principal.tenant_id, reason),
        )
        return run

    @staticmethod
    async def _signal_workflow(
        run_id: UUID,
        signal: str,
        notification: Awaitable[None],
    ) -> None:
        try:
            await notification
        except Exception as exc:
            raise WorkflowSignalFailed("run", str(run_id), signal) from exc

    async def snapshot(self, run_id: UUID, principal: Principal) -> dict[str, Any]:
        run = await self.get(run_id, principal)
        actions = await self._actions.list_for_run(run_id, principal.tenant_id)
        pending = [
            action
            for action in actions
            if action.status
            in {
                ActionStatus.PREPARED,
                ActionStatus.PENDING_APPROVAL,
                ActionStatus.APPROVED,
                ActionStatus.COMMITTING,
                ActionStatus.UNKNOWN,
            }
        ]
        total_tasks = len(run.plan.tasks) if run.plan is not None else 0
        completed_tasks = len(run.outputs)
        elapsed = int((run.updated_at - run.created_at).total_seconds())
        result_dump = getattr(run.result, "model_dump", None)
        return {
            "run_id": run.run_id,
            "status": run.status.value,
            "plan_version": run.current_plan_version,
            "progress": {
                "completed_tasks": completed_tasks,
                "total_tasks": total_tasks,
                "percent": int(run.progress * 100),
            },
            "budget": {
                "cost_usd": run.cost_actual_usd,
                "cost_limit_usd": run.contract.max_cost_usd,
                "tool_calls": run.tool_call_count,
                "elapsed_seconds": elapsed,
            },
            "current_step": self._current_step(run.status),
            "pending_actions": [
                {
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "risk": action.risk.value,
                    "expires_at": action.expires_at,
                }
                for action in pending
            ],
            "result": (result_dump(mode="json") if callable(result_dump) else run.result),
            "version": run.version,
            "updated_at": run.updated_at,
        }

    async def _create_and_append_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, bool, bool]:
        atomic_create = getattr(self._runs, "create_once_with_event", None)
        if callable(atomic_create):
            stored, created, _ = await atomic_create(
                run,
                event_type,
                payload,
                correlation_id,
            )
            retry_start = bool(getattr(self._runs, "retry_workflow_start_on_duplicate", False))
            return cast(RunRecord, stored), bool(created), retry_start

        stored, created = await self._runs.create_once(run)
        if created:
            await self._runs.append_event(
                stored,
                event_type,
                payload,
                correlation_id,
            )
        return cast(RunRecord, stored), bool(created), False

    async def _save_and_append_event(
        self,
        run: RunRecord,
        expected_version: int,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> RunRecord:
        atomic_save = getattr(self._runs, "save_with_event", None)
        if callable(atomic_save):
            stored, _ = await atomic_save(
                run,
                expected_version,
                event_type,
                payload,
                correlation_id,
            )
            return cast(RunRecord, stored)

        stored = cast(
            RunRecord,
            await self._runs.save(run, expected_version),
        )
        await self._runs.append_event(
            stored,
            event_type,
            payload,
            correlation_id,
        )
        return stored

    @staticmethod
    def _priority(request: CreateRunRequest) -> RunPriority:
        configured = request.constraints.get("priority")
        if isinstance(configured, str):
            try:
                return RunPriority(configured.strip().lower())
            except ValueError as exc:
                raise Conflict(
                    "INVALID_CONTRACT",
                    "Run priority is not recognized",
                    priority=configured,
                ) from exc
        risk = RunService._risk(request)
        if risk is RiskLevel.CRITICAL:
            return RunPriority.CRITICAL
        if risk is RiskLevel.HIGH:
            return RunPriority.HIGH
        return RunPriority.NORMAL

    @staticmethod
    def _risk(request: CreateRunRequest) -> RiskLevel:
        classifications = set(request.constraints.get("classifications", []))
        if classifications & {"secret", "restricted"}:
            return RiskLevel.CRITICAL
        if request.external_write_policy == "approval" or any(
            name.endswith(".prepare") for name in request.allowed_capabilities
        ):
            return RiskLevel.HIGH
        return RiskLevel.MEDIUM

    @staticmethod
    def _validate_capability_scope(
        request: CreateRunRequest,
        principal: Principal,
        data_scope: DataScope,
    ) -> None:
        if data_scope.tenant_id != principal.tenant_id:
            raise Conflict(
                "INVALID_CONTRACT",
                "Principal and data scope tenants differ",
            )
        resource_types = {name.split(".", 1)[0] for name in request.allowed_capabilities}
        if not resource_types <= set(data_scope.resource_types):
            raise Conflict(
                "DATA_SCOPE_DENIED",
                "Requested capabilities exceed the authenticated data scope",
                requested_resources=sorted(resource_types),
                allowed_resources=sorted(data_scope.resource_types),
            )
        if request.external_write_policy == "deny" and any(
            name.endswith(".prepare") for name in request.allowed_capabilities
        ):
            raise Conflict(
                "INVALID_CONTRACT",
                "Prepare capability conflicts with external_write_policy=deny",
            )

    async def _require_capabilities_enabled(
        self,
        tenant_id: str,
        requested: frozenset[str],
    ) -> None:
        if self._capabilities is None:
            return
        records = await self._capabilities.list(tenant_id)
        disabled = {record.name for record in records if not record.enabled}
        blocked = sorted(requested & disabled)
        if blocked:
            raise PlatformError(
                "CAPABILITY_DISABLED",
                "One or more requested capabilities are disabled",
                http_status=503,
                context={"capabilities": blocked},
            )

    async def _require_execution_allowed(
        self,
        *,
        tenant_id: str,
        use_case: str,
        capabilities: frozenset[str],
        operation: str,
    ) -> None:
        if self._kill_switches is None:
            return
        for capability in capabilities or frozenset({"*"}):
            await self._kill_switches.require_allowed(
                tenant_id=tenant_id,
                use_case=use_case,
                capability=capability,
                operation=operation,
            )

    @staticmethod
    def _request_use_case(request: CreateRunRequest) -> str:
        configured = request.constraints.get("use_case")
        return (
            configured
            if isinstance(configured, str) and configured.strip()
            else request.requested_output.format
        )

    @staticmethod
    def _contract_use_case(contract: TaskContract) -> str:
        configured = contract.constraints.get("use_case")
        return (
            configured
            if isinstance(configured, str) and configured.strip()
            else contract.requested_output.schema_name
        )

    @staticmethod
    def _contract_tenant_tier(contract: TaskContract) -> str:
        configured = contract.constraints.get("tenant_tier")
        return configured if isinstance(configured, str) and configured.strip() else "unknown"

    @staticmethod
    def _current_step(status: RunStatus) -> str:
        return {
            RunStatus.RECEIVED: "请求已接收",
            RunStatus.CLASSIFIED: "风险与合同已分类",
            RunStatus.PLANNING: "正在生成受限执行计划",
            RunStatus.AUTHORIZED: "计划已授权",
            RunStatus.EXECUTING: "正在执行计划",
            RunStatus.REPLANNING: "正在有限重规划",
            RunStatus.VERIFYING: "正在独立验证",
            RunStatus.WAITING_APPROVAL: "等待批准预览",
            RunStatus.PAUSED: "Run 已暂停",
            RunStatus.COMMITTING: "正在提交已批准动作",
            RunStatus.COMPENSATING: "正在补偿外部动作",
            RunStatus.COMPLETED: "已完成",
            RunStatus.FAILED: "执行失败",
            RunStatus.CANCELLED: "已取消",
        }[status]
