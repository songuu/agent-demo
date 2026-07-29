"""Temporal transaction-plane workflow for explicit Action recovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

RECOVERY_RETRY_POLICY = RetryPolicy(maximum_attempts=1)
SUPPORTED_RECOVERY_OPERATIONS = frozenset({"reconcile", "compensate"})


@dataclass(frozen=True, slots=True)
class StartActionRecoveryCommand:
    """Versioned, secret-free request scheduled onto the commit task queue."""

    run_id: str
    action_id: str
    tenant_id: str
    correlation_id: str
    requested_by: str
    operation: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.run_id,
                self.action_id,
                self.tenant_id,
                self.correlation_id,
                self.requested_by,
            )
        ):
            raise ValueError("ACTION_RECOVERY_IDENTIFIERS_REQUIRED")
        if self.operation not in SUPPORTED_RECOVERY_OPERATIONS:
            raise ValueError("ACTION_RECOVERY_OPERATION_UNSUPPORTED")
        if self.operation == "compensate" and not (self.reason or "").strip():
            raise ValueError("ACTION_RECOVERY_COMPENSATION_REASON_REQUIRED")


@workflow.defn
class ActionRecoveryWorkflow:
    """Run reconciliation/compensation only in the transaction plane.

    This workflow is registered exclusively by the commit worker. Its command
    intentionally contains no provider credential or secret material; the
    commit worker obtains a short-lived credential inside the Activity.
    """

    def __init__(self) -> None:
        self.phase = "received"

    @workflow.query
    def summary(self) -> dict[str, str]:
        return {"phase": self.phase}

    @workflow.run
    async def run(self, command: StartActionRecoveryCommand) -> dict[str, Any]:
        self.phase = command.operation
        activity_name = (
            "transaction.reconcile_action"
            if command.operation == "reconcile"
            else "transaction.compensate_action"
        )
        payload = {
            "run_id": command.run_id,
            "action_id": command.action_id,
            "tenant_id": command.tenant_id,
            "correlation_id": command.correlation_id,
            "requested_by": command.requested_by,
            "operation": command.operation,
            "reason": command.reason,
        }
        result = await workflow.execute_activity(
            activity_name,
            payload,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RECOVERY_RETRY_POLICY,
            activity_id=f"{command.operation}-{command.action_id}",
        )
        self.phase = "completed"
        return {
            **result,
            "status": "completed",
            "operation": command.operation,
            "run_id": command.run_id,
            "action_id": command.action_id,
        }
