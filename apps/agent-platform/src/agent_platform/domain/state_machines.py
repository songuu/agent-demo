"""Explicit Run and Action state machines with fail-closed transitions."""

from __future__ import annotations

from .enums import ActionStatus, RunStatus
from .errors import DomainTransitionError

RUN_TERMINAL_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.FAILED,
    RunStatus.CANCELLED,
}

ACTION_TERMINAL_STATUSES = {
    ActionStatus.REJECTED,
    ActionStatus.EXPIRED,
    ActionStatus.COMPENSATED,
    ActionStatus.COMPENSATION_FAILED,
    ActionStatus.CANCELLED,
}

_RUN_TRANSITIONS: dict[RunStatus, frozenset[RunStatus]] = {
    RunStatus.RECEIVED: frozenset({RunStatus.CLASSIFIED, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.CLASSIFIED: frozenset({RunStatus.PLANNING, RunStatus.FAILED, RunStatus.CANCELLED}),
    RunStatus.PLANNING: frozenset(
        {
            RunStatus.AUTHORIZED,
            RunStatus.REPLANNING,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.AUTHORIZED: frozenset(
        {
            RunStatus.EXECUTING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.EXECUTING: frozenset(
        {
            RunStatus.REPLANNING,
            RunStatus.VERIFYING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.COMMITTING,
            RunStatus.COMPENSATING,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.REPLANNING: frozenset(
        {
            RunStatus.AUTHORIZED,
            RunStatus.EXECUTING,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.VERIFYING: frozenset(
        {
            RunStatus.REPLANNING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.COMMITTING,
            RunStatus.COMPENSATING,
            RunStatus.COMPLETED,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.WAITING_APPROVAL: frozenset(
        {
            RunStatus.COMMITTING,
            RunStatus.EXECUTING,
            RunStatus.REPLANNING,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.COMMITTING: frozenset(
        {
            RunStatus.VERIFYING,
            RunStatus.COMPENSATING,
            RunStatus.COMPLETED,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.COMPENSATING: frozenset(
        {
            RunStatus.VERIFYING,
            RunStatus.COMPLETED,
            RunStatus.PAUSED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    # The persisted prior state determines the precise resume target. These
    # targets are the only states from which a pause is supported above.
    RunStatus.PAUSED: frozenset(
        {
            RunStatus.PLANNING,
            RunStatus.AUTHORIZED,
            RunStatus.EXECUTING,
            RunStatus.REPLANNING,
            RunStatus.VERIFYING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.COMMITTING,
            RunStatus.COMPENSATING,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
    ),
    RunStatus.COMPLETED: frozenset(),
    RunStatus.FAILED: frozenset(),
    RunStatus.CANCELLED: frozenset(),
}

_ACTION_TRANSITIONS: dict[ActionStatus, frozenset[ActionStatus]] = {
    ActionStatus.PROPOSED: frozenset({ActionStatus.PREPARED, ActionStatus.CANCELLED}),
    ActionStatus.PREPARED: frozenset(
        {
            ActionStatus.PENDING_APPROVAL,
            ActionStatus.APPROVED,
            ActionStatus.EXPIRED,
            ActionStatus.CANCELLED,
        }
    ),
    ActionStatus.PENDING_APPROVAL: frozenset(
        {
            ActionStatus.APPROVED,
            ActionStatus.REJECTED,
            ActionStatus.EXPIRED,
            ActionStatus.CANCELLED,
        }
    ),
    ActionStatus.APPROVED: frozenset(
        {
            ActionStatus.COMMITTING,
            ActionStatus.EXPIRED,
            ActionStatus.CANCELLED,
        }
    ),
    ActionStatus.COMMITTING: frozenset(
        {
            ActionStatus.UNKNOWN,
            ActionStatus.COMMITTED,
            ActionStatus.VERIFY_FAILED,
        }
    ),
    # UNKNOWN never retries directly. A proven-absent reconciliation may move
    # back to APPROVED through the guarded exception in ensure_action_transition.
    ActionStatus.UNKNOWN: frozenset(
        {
            ActionStatus.COMMITTED,
            ActionStatus.VERIFY_FAILED,
            ActionStatus.EXPIRED,
            ActionStatus.CANCELLED,
        }
    ),
    ActionStatus.COMMITTED: frozenset({ActionStatus.COMPENSATING}),
    ActionStatus.VERIFY_FAILED: frozenset(
        {ActionStatus.COMMITTED, ActionStatus.COMPENSATING, ActionStatus.CANCELLED}
    ),
    ActionStatus.COMPENSATING: frozenset(
        {
            ActionStatus.COMPENSATED,
            ActionStatus.COMPENSATION_FAILED,
        }
    ),
    ActionStatus.REJECTED: frozenset(),
    ActionStatus.EXPIRED: frozenset(),
    ActionStatus.COMPENSATED: frozenset(),
    ActionStatus.COMPENSATION_FAILED: frozenset(),
    ActionStatus.CANCELLED: frozenset(),
}


def ensure_run_transition(
    current: RunStatus,
    target: RunStatus,
    *,
    run_id: str | None = None,
) -> None:
    if target in _RUN_TRANSITIONS[current]:
        return
    raise DomainTransitionError(
        "INVALID_STATE_TRANSITION",
        "run transition is not allowed",
        context={
            "entity": "run",
            "entity_id": run_id,
            "current": current.value,
            "target": target.value,
        },
    )


def ensure_action_transition(
    current: ActionStatus,
    target: ActionStatus,
    *,
    action_id: str | None = None,
    reconciliation_confirmed_absent: bool = False,
) -> None:
    if target in _ACTION_TRANSITIONS[current]:
        return
    if (
        current is ActionStatus.UNKNOWN
        and target is ActionStatus.APPROVED
        and reconciliation_confirmed_absent
    ):
        return
    raise DomainTransitionError(
        "INVALID_STATE_TRANSITION",
        "action transition is not allowed",
        context={
            "entity": "action",
            "entity_id": action_id,
            "current": current.value,
            "target": target.value,
            "reconciliation_confirmed_absent": reconciliation_confirmed_absent,
        },
    )
