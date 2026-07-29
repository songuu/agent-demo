"""Deterministic Temporal workflow for bounded Agent runs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

WORKFLOW_PATCH_ID = "agent-run-v1-bounded-controls"
APPROVAL_TIMEOUT = timedelta(hours=24)
STANDARD_RETRY_POLICY = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=2),
    maximum_interval=timedelta(seconds=30),
)
COMMIT_RETRY_POLICY = RetryPolicy(maximum_attempts=1)


@dataclass(frozen=True, slots=True)
class StartRunCommand:
    run_id: str
    tenant_id: str
    correlation_id: str
    max_replans: int = 2
    max_duration_seconds: int = 900
    max_tool_calls: int = 100
    approval_timeout_seconds: int = 86_400
    commit_task_queue: str = "agent-commits"

    def __post_init__(self) -> None:
        if (
            not self.run_id
            or not self.tenant_id
            or not self.correlation_id
            or not self.commit_task_queue.strip()
        ):
            raise ValueError("START_RUN_COMMAND_IDENTIFIERS_REQUIRED")
        if not 0 <= self.max_replans <= 5:
            raise ValueError("START_RUN_COMMAND_MAX_REPLANS_INVALID")
        if not 5 <= self.max_duration_seconds <= 86_400:
            raise ValueError("START_RUN_COMMAND_DURATION_INVALID")
        if not 0 <= self.max_tool_calls <= 10_000:
            raise ValueError("START_RUN_COMMAND_TOOL_BUDGET_INVALID")
        if not 1 <= self.approval_timeout_seconds <= 86_400:
            raise ValueError("START_RUN_COMMAND_APPROVAL_TIMEOUT_INVALID")


@workflow.defn
class AgentRunWorkflow:
    """Own lifecycle, timers, retries, signals, and bounded re-planning.

    Model, tool, database, and commit work stays in Activities. The workflow
    only operates on versioned, JSON-compatible commands and results so replay
    does not depend on database or SDK object identity.
    """

    def __init__(self) -> None:
        self.cancel_requested = False
        self.cancel_reason: str | None = None
        self.paused = False
        self.pause_reason: str | None = None
        self.approval_decisions: dict[str, str] = {}
        self.phase = "received"
        self.replan_count = 0
        self.workflow_version = "uninitialized"

    @workflow.signal
    async def cancel(self, reason: str) -> None:
        self.cancel_requested = True
        self.cancel_reason = reason or "cancel requested"

    @workflow.signal
    async def pause(self, reason: str) -> None:
        self.paused = True
        self.pause_reason = reason or "pause requested"

    @workflow.signal
    async def resume(self) -> None:
        self.paused = False
        self.pause_reason = None

    @workflow.signal
    async def decide_action(self, action_id: str, decision: str) -> None:
        normalized = decision.casefold()
        if normalized not in {"approved", "rejected"}:
            return
        self.approval_decisions[action_id] = normalized

    @workflow.query
    def summary(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "cancel_requested": self.cancel_requested,
            "cancel_reason": self.cancel_reason,
            "paused": self.paused,
            "pause_reason": self.pause_reason,
            "approval_decisions": dict(self.approval_decisions),
            "pending_approvals": sorted(self.approval_decisions),
            "replan_count": self.replan_count,
            "workflow_version": self.workflow_version,
        }

    @workflow.run
    async def run(self, command: StartRunCommand) -> dict[str, Any]:
        try:
            return await self._run_steps(command)
        except ActivityError as exc:
            reason = self._activity_failure_reason(
                exc,
                fallback="ACTIVITY_FAILED",
            )
            if reason != "BUDGET_EXHAUSTED":
                raise
            # The Activity persisted actual usage before surfacing the hard
            # gate. Mark the Run terminal without starting another model/tool.
            await self._fail(command, reason)
            return self._failed_result(reason)

    async def _run_steps(self, command: StartRunCommand) -> dict[str, Any]:
        # The marker keeps a replay-safe branch point for the next workflow
        # evolution. Never delete a patch until all histories have aged out.
        if workflow.patched(WORKFLOW_PATCH_ID):
            self.workflow_version = WORKFLOW_PATCH_ID
        else:
            self.workflow_version = "legacy"

        base = {
            "run_id": command.run_id,
            "tenant_id": command.tenant_id,
            "correlation_id": command.correlation_id,
        }
        self.phase = "classified"
        await self._activity("agent.classify_contract", base, seconds=30)
        if not await self._control_gate(command):
            return self._cancelled_result()

        self.phase = "planning"
        plan = await self._activity("agent.create_plan", base, seconds=180)
        await self._activity(
            "agent.authorize_plan",
            {**base, "plan": plan},
            seconds=30,
        )

        report: dict[str, Any]
        outputs: dict[str, Any]
        while True:
            if not await self._control_gate(command):
                return self._cancelled_result()
            self.phase = "executing"
            await self._activity("agent.mark_executing", base, seconds=30)
            outputs = await self._execute_plan(command, plan)
            if not await self._control_gate(command):
                return self._cancelled_result()

            self.phase = "verifying"
            report = await self._activity(
                "agent.verify_run",
                {**base, "plan": plan, "outputs": outputs},
                seconds=300,
            )
            if report.get("verdict") != "revise":
                break
            if self.replan_count >= command.max_replans:
                await self._fail(command, "MAX_REPLANS_EXHAUSTED")
                return self._failed_result("MAX_REPLANS_EXHAUSTED")

            self.replan_count += 1
            self.phase = "replanning"
            plan = await self._activity(
                "agent.revise_plan",
                {
                    **base,
                    "plan": plan,
                    "report": report,
                    "replan_count": self.replan_count,
                },
                seconds=180,
            )

        if report.get("verdict") != "pass":
            await self._fail(command, "VERIFICATION_ESCALATION_UNRESOLVED")
            return self._failed_result("VERIFICATION_ESCALATION_UNRESOLVED")

        actions = await self._activity("agent.list_actions", base, seconds=30)
        if actions:
            approved = await self._await_approvals(command, actions)
            if approved is None:
                return self._cancelled_result()
            if not approved:
                return self._failed_result("ACTION_NOT_APPROVED")
            actions = await self._activity("agent.list_actions", base, seconds=30)
            self.phase = "committing"
            for action in sorted(actions, key=lambda item: str(item["action_id"])):
                if action.get("status") != "approved":
                    continue
                try:
                    await workflow.execute_activity(
                        "agent.commit_action",
                        {**base, "action_id": str(action["action_id"])},
                        start_to_close_timeout=timedelta(minutes=10),
                        retry_policy=COMMIT_RETRY_POLICY,
                        activity_id=f"commit-{action['action_id']}",
                        task_queue=command.commit_task_queue,
                    )
                except ActivityError as exc:
                    # The Action Activity has already persisted its exact
                    # checkpoint (for example UNKNOWN). Persist the Run failure
                    # separately so orchestration never remains COMMITTING.
                    reason = self._activity_failure_reason(
                        exc,
                        fallback="COMMIT_ACTIVITY_FAILED",
                    )
                    await self._fail(command, reason)
                    return self._failed_result(reason)

        if not await self._control_gate(command):
            return self._cancelled_result()
        self.phase = "finalizing"
        await self._activity(
            "agent.finalize_run",
            {**base, "plan": plan, "outputs": outputs, "report": report},
            seconds=180,
        )
        self.phase = "completed"
        return {
            "status": "completed",
            "run_id": command.run_id,
            "replan_count": self.replan_count,
            "workflow_version": self.workflow_version,
        }

    async def _execute_plan(
        self,
        command: StartRunCommand,
        plan: dict[str, Any],
    ) -> dict[str, Any]:
        tasks = {str(item["id"]): item for item in plan.get("tasks", [])}
        if not tasks:
            raise ValueError("TEMPORAL_PLAN_HAS_NO_TASKS")
        planned_tool_calls = sum(int(task.get("max_tool_calls", 0)) for task in tasks.values())
        if planned_tool_calls > command.max_tool_calls:
            raise ValueError("BUDGET_EXHAUSTED: plan exceeds the TaskContract tool-call budget")
        outputs: dict[str, Any] = {}
        pending = set(tasks)
        base = {
            "run_id": command.run_id,
            "tenant_id": command.tenant_id,
            "correlation_id": command.correlation_id,
            "plan_version": int(plan["plan_version"]),
        }
        while pending:
            ready = [
                tasks[task_id]
                for task_id in sorted(pending)
                if set(tasks[task_id].get("depends_on", [])) <= set(outputs)
            ]
            if not ready:
                raise ValueError("TEMPORAL_PLAN_DEPENDENCY_CYCLE")
            calls = [
                workflow.execute_activity(
                    "agent.execute_task",
                    {
                        **base,
                        "task": task,
                        "dependencies": {
                            dependency: outputs[dependency]
                            for dependency in task.get("depends_on", [])
                        },
                    },
                    start_to_close_timeout=timedelta(seconds=int(task.get("timeout_seconds", 90))),
                    heartbeat_timeout=timedelta(seconds=15),
                    retry_policy=STANDARD_RETRY_POLICY,
                    activity_id=(f"task-{plan['plan_version']}-{task['id']}"),
                )
                for task in ready
            ]
            batch = await asyncio.gather(*calls)
            for task, output in zip(ready, batch, strict=True):
                task_id = str(task["id"])
                outputs[task_id] = output
                pending.remove(task_id)
            if self.cancel_requested:
                break
        return outputs

    async def _await_approvals(
        self,
        command: StartRunCommand,
        actions: list[dict[str, Any]],
    ) -> bool | None:
        self.phase = "waiting_approval"
        base = {
            "run_id": command.run_id,
            "tenant_id": command.tenant_id,
            "correlation_id": command.correlation_id,
        }
        await self._activity("agent.mark_waiting_approval", base, seconds=30)
        expected = {
            str(action["action_id"])
            for action in actions
            if action.get("status") not in {"approved", "rejected", "expired", "cancelled"}
        }
        if not actions:
            expected = {"run"}
        for action in actions:
            status = str(action.get("status", ""))
            if status in {"approved", "rejected"}:
                self.approval_decisions[str(action["action_id"])] = status
        if any(
            str(action.get("status", "")) in {"rejected", "expired", "cancelled"}
            for action in actions
        ):
            await self._fail(command, "ACTION_NOT_APPROVED")
            return False

        deadline = workflow.now() + timedelta(seconds=command.approval_timeout_seconds)
        while not expected <= set(self.approval_decisions):
            remaining = deadline - workflow.now()
            if remaining <= timedelta(0):
                return await self._close_approval_timeout(command, base, expected)
            try:
                await workflow.wait_condition(
                    lambda: (
                        self.cancel_requested
                        or (not self.paused and expected <= set(self.approval_decisions))
                    ),
                    timeout=remaining,
                )
            except TimeoutError:
                return await self._close_approval_timeout(command, base, expected)
            if self.cancel_requested:
                await self._cancel(command)
                return None

        if any(self.approval_decisions[action_id] == "rejected" for action_id in expected):
            await self._fail(command, "ACTION_REJECTED")
            return False
        return True

    async def _close_approval_timeout(
        self,
        command: StartRunCommand,
        base: dict[str, str],
        expected: set[str],
    ) -> bool:
        result = await self._activity("agent.expire_actions", base, seconds=30)
        statuses = result.get("statuses") if isinstance(result, dict) else None
        if (
            isinstance(statuses, dict)
            and expected
            and all(statuses.get(action_id) == "approved" for action_id in expected)
        ):
            self.approval_decisions.update({action_id: "approved" for action_id in expected})
            return True
        await self._fail(command, "APPROVAL_TIMEOUT")
        return False

    async def _control_gate(self, command: StartRunCommand) -> bool:
        if self.cancel_requested:
            await self._cancel(command)
            return False
        if self.paused:
            await workflow.wait_condition(lambda: not self.paused or self.cancel_requested)
        if self.cancel_requested:
            await self._cancel(command)
            return False
        return True

    async def _cancel(self, command: StartRunCommand) -> None:
        self.phase = "cancelled"
        await self._activity(
            "agent.cancel_run",
            {
                "run_id": command.run_id,
                "tenant_id": command.tenant_id,
                "correlation_id": command.correlation_id,
                "reason": self.cancel_reason or "RUN_CANCELLED",
            },
            seconds=30,
        )

    async def _fail(self, command: StartRunCommand, reason: str) -> None:
        self.phase = "failed"
        await self._activity(
            "agent.fail_run",
            {
                "run_id": command.run_id,
                "tenant_id": command.tenant_id,
                "correlation_id": command.correlation_id,
                "reason": reason,
            },
            seconds=30,
        )

    async def _activity(
        self,
        name: str,
        payload: dict[str, Any],
        *,
        seconds: int,
    ) -> Any:
        return await workflow.execute_activity(
            name,
            payload,
            start_to_close_timeout=timedelta(seconds=seconds),
            retry_policy=STANDARD_RETRY_POLICY,
        )

    @staticmethod
    def _activity_failure_reason(
        error: BaseException,
        *,
        fallback: str,
    ) -> str:
        current: BaseException | None = error
        for _ in range(5):
            if current is None:
                break
            if isinstance(current, ApplicationError) and current.type:
                return current.type
            cause = getattr(current, "cause", None)
            current = cause if isinstance(cause, BaseException) else current.__cause__
            if current is None:
                break
        return fallback

    def _cancelled_result(self) -> dict[str, Any]:
        return {
            "status": "cancelled",
            "replan_count": self.replan_count,
            "workflow_version": self.workflow_version,
        }

    def _failed_result(self, reason: str) -> dict[str, Any]:
        return {
            "status": "failed",
            "reason": reason,
            "replan_count": self.replan_count,
            "workflow_version": self.workflow_version,
        }
