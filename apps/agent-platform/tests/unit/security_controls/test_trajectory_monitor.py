from __future__ import annotations

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.trajectory_monitor import (
    TrajectoryMonitor,
    TrajectorySnapshot,
)
from agent_platform.domain.enums import TrajectoryAction


def snapshot(**overrides: object) -> TrajectorySnapshot:
    values: dict[str, object] = {
        "goal_similarity": 0.98,
        "denied_scope_attempts": 0,
        "unplanned_tool_calls": 0,
        "injection_indicators": 0,
        "credential_access_attempts": 0,
        "classification_escalations": 0,
        "retry_count": 0,
        "sensitive_read_then_egress": False,
        "candidate_capabilities": frozenset(),
        "evidence_event_ids": (),
    }
    values.update(overrides)
    return TrajectorySnapshot(**values)


def test_trajectory_monitor_emits_all_control_actions() -> None:
    monitor = TrajectoryMonitor()
    assert monitor.evaluate(snapshot()).action is TrajectoryAction.CONTINUE
    assert (
        monitor.evaluate(
            snapshot(
                goal_similarity=0.65,
                evidence_event_ids=(1,),
            )
        ).action
        is TrajectoryAction.WARN
    )
    restricted = monitor.evaluate(
        snapshot(
            denied_scope_attempts=2,
            candidate_capabilities=frozenset({"network.http"}),
            evidence_event_ids=(2, 3),
        )
    )
    assert restricted.action is TrajectoryAction.RESTRICT
    assert restricted.disabled_capabilities == {"network.http"}
    assert (
        monitor.evaluate(
            snapshot(
                injection_indicators=2,
                evidence_event_ids=(4, 5),
            )
        ).action
        is TrajectoryAction.PAUSE
    )
    assert (
        monitor.evaluate(
            snapshot(
                sensitive_read_then_egress=True,
                evidence_event_ids=(6,),
            )
        ).action
        is TrajectoryAction.TERMINATE
    )


def test_trajectory_monitor_requires_evidence_for_nonzero_security_signals() -> None:
    with pytest.raises(PlatformError, match="TRAJECTORY_EVIDENCE_REQUIRED"):
        TrajectoryMonitor().evaluate(snapshot(denied_scope_attempts=2))
