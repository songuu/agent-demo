from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_platform.domain.enums import ActionStatus, RunStatus
from agent_platform.workflows.activities import (
    ActivityDependencies,
    TemporalActivities,
)
from agent_platform.workflows.recovery_workflow import (
    ActionRecoveryWorkflow,
    StartActionRecoveryCommand,
)


class _Repository:
    def __init__(self, value: object) -> None:
        self.value = value

    async def get(self, *_: object) -> object:
        return self.value


class _RunService:
    def __init__(self, run: SimpleNamespace) -> None:
        self.run = run
        self.transitions: list[tuple[RunStatus, str]] = []

    async def transition(
        self,
        run_id: object,
        tenant_id: str,
        target: RunStatus,
        correlation_id: str,
        *,
        reason_code: str,
    ) -> SimpleNamespace:
        del run_id, tenant_id, correlation_id
        self.transitions.append((target, reason_code))
        self.run.status = target
        return self.run


class _CommitService:
    def __init__(self, action: SimpleNamespace) -> None:
        self.action = action
        self.reconcile_kwargs: dict[str, object] | None = None
        self.compensate_kwargs: dict[str, object] | None = None

    async def reconcile_unknown(self, **kwargs: object) -> None:
        self.reconcile_kwargs = kwargs
        self.action.status = ActionStatus.APPROVED

    async def compensate(self, **kwargs: object) -> dict[str, bool]:
        self.compensate_kwargs = kwargs
        self.action.status = ActionStatus.COMPENSATED
        return {"compensated": True}


def _activities(
    *,
    run_status: RunStatus = RunStatus.COMMITTING,
    action_status: ActionStatus = ActionStatus.UNKNOWN,
) -> tuple[TemporalActivities, _CommitService, _RunService]:
    run = SimpleNamespace(run_id=uuid4(), status=run_status)
    action = SimpleNamespace(action_id=uuid4(), status=action_status)
    commit_service = _CommitService(action)
    run_service = _RunService(run)
    store = SimpleNamespace(
        runs=_Repository(run),
        actions=_Repository(action),
    )
    dependencies = ActivityDependencies(
        store=store,
        runtime=None,
        gateway=None,
        run_service=run_service,
        commit_service=commit_service,
        commit_scopes=frozenset({"business:commit"}),
    )
    return TemporalActivities(dependencies), commit_service, run_service


@pytest.mark.asyncio
async def test_reconcile_activity_uses_commit_worker_identity_and_settles_stuck_run() -> None:
    bridge, service, runs = _activities()
    payload = {
        "run_id": str(uuid4()),
        "action_id": str(uuid4()),
        "tenant_id": "tenant-a",
        "correlation_id": "recovery-1",
        "requested_by": "admin-a",
    }

    result = await bridge.reconcile_action(payload)

    assert result["action_status"] == "approved"
    assert service.reconcile_kwargs is not None
    assert service.reconcile_kwargs["tenant_id"] == "tenant-a"
    assert service.reconcile_kwargs["principal_id"] == "commit-worker"
    assert service.reconcile_kwargs["principal_scopes"] == frozenset({"business:commit"})
    assert str(service.reconcile_kwargs["action_id"]) == payload["action_id"]
    assert service.reconcile_kwargs["correlation_id"] == "recovery-1"
    assert runs.transitions == [
        (
            RunStatus.FAILED,
            "ACTION_RECOVERY_RECONCILE_APPROVED",
        )
    ]


@pytest.mark.asyncio
async def test_compensate_activity_marks_transaction_plane_and_finishes_failed() -> None:
    bridge, service, runs = _activities(action_status=ActionStatus.COMMITTED)
    payload = {
        "run_id": str(uuid4()),
        "action_id": str(uuid4()),
        "tenant_id": "tenant-a",
        "correlation_id": "recovery-2",
        "requested_by": "admin-a",
        "reason": "operator requested rollback",
    }

    result = await bridge.compensate_action(payload)

    assert result["action_status"] == "compensated"
    assert service.compensate_kwargs is not None
    assert service.compensate_kwargs["principal_id"] == "commit-worker"
    assert service.compensate_kwargs["principal_scopes"] == frozenset({"business:commit"})
    assert service.compensate_kwargs["reason"] == "operator requested rollback"
    assert runs.transitions == [
        (RunStatus.COMPENSATING, "ACTION_RECOVERY_COMPENSATION_STARTED"),
        (RunStatus.FAILED, "ACTION_RECOVERY_COMPENSATE_COMPENSATED"),
    ]


@pytest.mark.parametrize(
    ("operation", "reason"),
    [
        ("delete", None),
        ("compensate", None),
        ("compensate", " "),
    ],
)
def test_recovery_command_rejects_unsupported_or_unexplained_operations(
    operation: str,
    reason: str | None,
) -> None:
    with pytest.raises(ValueError, match="ACTION_RECOVERY"):
        StartActionRecoveryCommand(
            run_id=str(uuid4()),
            action_id=str(uuid4()),
            tenant_id="tenant-a",
            correlation_id="recovery-command-1",
            requested_by="admin-a",
            operation=operation,
            reason=reason,
        )


def test_recovery_workflow_is_a_distinct_transaction_plane_type() -> None:
    assert ActionRecoveryWorkflow.__name__ == "ActionRecoveryWorkflow"
