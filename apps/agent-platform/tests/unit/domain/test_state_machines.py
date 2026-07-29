from __future__ import annotations

import sys
import unittest
from itertools import pairwise
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import ActionStatus, RunStatus
from agent_platform.domain.errors import DomainTransitionError
from agent_platform.domain.state_machines import (
    ACTION_TERMINAL_STATUSES,
    RUN_TERMINAL_STATUSES,
    ensure_action_transition,
    ensure_run_transition,
)


class RunStateMachineTests(unittest.TestCase):
    def test_happy_path_and_controlled_pause_resume(self) -> None:
        path = [
            RunStatus.RECEIVED,
            RunStatus.CLASSIFIED,
            RunStatus.PLANNING,
            RunStatus.AUTHORIZED,
            RunStatus.EXECUTING,
            RunStatus.PAUSED,
            RunStatus.EXECUTING,
            RunStatus.VERIFYING,
            RunStatus.COMPLETED,
        ]
        for current, target in pairwise(path):
            with self.subTest(current=current, target=target):
                ensure_run_transition(current, target)

    def test_illegal_transition_contains_business_context(self) -> None:
        with self.assertRaises(DomainTransitionError) as caught:
            ensure_run_transition(
                RunStatus.RECEIVED,
                RunStatus.COMPLETED,
                run_id="run-123",
            )
        error = caught.exception
        self.assertEqual(error.code, "INVALID_STATE_TRANSITION")
        self.assertEqual(error.context["entity"], "run")
        self.assertEqual(error.context["entity_id"], "run-123")
        self.assertEqual(error.context["current"], "received")
        self.assertEqual(error.context["target"], "completed")

    def test_run_terminal_states_are_immutable(self) -> None:
        self.assertEqual(
            RUN_TERMINAL_STATUSES,
            {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED},
        )
        for terminal in RUN_TERMINAL_STATUSES:
            with self.subTest(terminal=terminal), self.assertRaises(
                DomainTransitionError
            ):
                ensure_run_transition(terminal, RunStatus.EXECUTING)


class ActionStateMachineTests(unittest.TestCase):
    def test_unknown_must_reconcile_without_blind_retry(self) -> None:
        ensure_action_transition(ActionStatus.COMMITTING, ActionStatus.UNKNOWN)
        ensure_action_transition(ActionStatus.UNKNOWN, ActionStatus.COMMITTED)
        ensure_action_transition(ActionStatus.UNKNOWN, ActionStatus.VERIFY_FAILED)
        with self.assertRaises(DomainTransitionError):
            ensure_action_transition(ActionStatus.UNKNOWN, ActionStatus.COMMITTING)

        with self.assertRaises(DomainTransitionError):
            ensure_action_transition(ActionStatus.UNKNOWN, ActionStatus.APPROVED)
        ensure_action_transition(
            ActionStatus.UNKNOWN,
            ActionStatus.APPROVED,
            reconciliation_confirmed_absent=True,
        )

    def test_approval_and_compensation_paths(self) -> None:
        path = [
            ActionStatus.PROPOSED,
            ActionStatus.PREPARED,
            ActionStatus.PENDING_APPROVAL,
            ActionStatus.APPROVED,
            ActionStatus.COMMITTING,
            ActionStatus.COMMITTED,
            ActionStatus.COMPENSATING,
            ActionStatus.COMPENSATED,
        ]
        for current, target in pairwise(path):
            ensure_action_transition(current, target)

    def test_action_terminal_states_are_immutable(self) -> None:
        self.assertIn(ActionStatus.REJECTED, ACTION_TERMINAL_STATUSES)
        self.assertIn(ActionStatus.COMPENSATION_FAILED, ACTION_TERMINAL_STATUSES)
        for terminal in ACTION_TERMINAL_STATUSES:
            with self.subTest(terminal=terminal), self.assertRaises(
                DomainTransitionError
            ):
                ensure_action_transition(terminal, ActionStatus.PREPARED)


if __name__ == "__main__":
    unittest.main()
