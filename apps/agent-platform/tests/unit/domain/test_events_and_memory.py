from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import (
    DataClassification,
    DomainEvent,
    MemoryCandidate,
    RunEventType,
    TrustLevel,
)


def test_domain_event_is_tenant_bound_versioned_and_hashable() -> None:
    event = DomainEvent(
        event_id=uuid4(),
        run_id=uuid4(),
        tenant_id="tenant-1",
        sequence_no=7,
        event_type=RunEventType.TASK_COMPLETED,
        actor_type="worker",
        actor_id="worker-1",
        correlation_id="corr-1",
        occurred_at=datetime.now(UTC),
        payload={"task_id": "research-a", "plan_version": 2},
    )

    assert event.schema_version == "1.0"
    assert event.payload_hash is not None
    assert len(event.payload_hash) == 64


def test_domain_event_rejects_secret_bearing_payloads_and_naive_time() -> None:
    with pytest.raises(ValidationError, match="EVENT_SENSITIVE_FIELD_FORBIDDEN"):
        DomainEvent(
            run_id=uuid4(),
            tenant_id="tenant-1",
            sequence_no=1,
            event_type=RunEventType.RUN_STATUS_CHANGED,
            actor_type="api",
            actor_id="api-1",
            correlation_id="corr-1",
            payload={"nested": {"api_key": "must-not-enter-audit-log"}},
        )

    with pytest.raises(ValidationError, match="TIMEZONE_REQUIRED"):
        DomainEvent(
            run_id=uuid4(),
            tenant_id="tenant-1",
            sequence_no=1,
            event_type=RunEventType.RUN_STATUS_CHANGED,
            actor_type="api",
            actor_id="api-1",
            correlation_id="corr-1",
            occurred_at=datetime(2026, 7, 23, 12, 0),
            payload={},
        )


def test_memory_candidate_requires_provenance_and_user_visibility() -> None:
    candidate = MemoryCandidate(
        subject_type="project",
        subject_id="project-1",
        memory_type="decision",
        content={"decision": "Use bounded workflows"},
        source_refs=["event://7", "artifact://report-1"],
        classification=DataClassification.INTERNAL,
        confidence=Decimal("0.9500"),
        purpose="Preserve an approved architecture decision",
        owner_id="user-1",
        write_policy="explicit_approval",
        user_visible=True,
        trust=TrustLevel.TRUSTED,
        expires_at=datetime.now(UTC) + timedelta(days=365),
    )
    assert candidate.source_refs == ["event://7", "artifact://report-1"]

    with pytest.raises(ValidationError, match="MEMORY_PROVENANCE_REQUIRED"):
        MemoryCandidate(
            subject_type="project",
            subject_id="project-1",
            memory_type="decision",
            content={"decision": "Unattributed"},
            source_refs=[],
            classification=DataClassification.INTERNAL,
            confidence=Decimal("0.9500"),
            purpose="Preserve an architecture decision",
            owner_id="user-1",
            write_policy="automatic",
            user_visible=True,
        )

    with pytest.raises(ValidationError, match="MEMORY_USER_VISIBILITY_REQUIRED"):
        MemoryCandidate(
            subject_type="user",
            subject_id="user-1",
            memory_type="preference",
            content={"preference": "hidden inference"},
            source_refs=["event://9"],
            classification=DataClassification.CONFIDENTIAL,
            confidence=Decimal("0.5000"),
            purpose="Build a user profile",
            owner_id="user-1",
            write_policy="automatic",
            user_visible=False,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
