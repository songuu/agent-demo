"""Durable, deterministic whole-trajectory safety controls."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import AuditEvent, EventRecord, RunRecord
from agent_platform.domain.enums import RunStatus, TrajectoryAction
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import DataScope
from agent_platform.domain.policies import TrajectoryDecision
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


class TrajectorySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    goal_similarity: float = Field(ge=0, le=1)
    denied_scope_attempts: int = Field(ge=0, le=1_000)
    unplanned_tool_calls: int = Field(ge=0, le=1_000)
    injection_indicators: int = Field(ge=0, le=1_000)
    credential_access_attempts: int = Field(ge=0, le=1_000)
    classification_escalations: int = Field(ge=0, le=1_000)
    retry_count: int = Field(ge=0, le=10_000)
    sensitive_read_then_egress: bool
    denial_bypass_attempts: int = Field(default=0, ge=0, le=1_000)
    repeated_operation_count: int = Field(default=0, ge=0, le=10_000)
    scope_escalations: int = Field(default=0, ge=0, le=1_000)
    untrusted_write_attempts: int = Field(default=0, ge=0, le=1_000)
    unresolved_candidates: int = Field(default=0, ge=0, le=1_000)
    candidate_capabilities: frozenset[str] = Field(default_factory=frozenset)
    evidence_event_ids: tuple[int, ...] = ()

    @model_validator(mode="after")
    def validate_event_ids(self) -> Self:
        if any(event_id < 1 for event_id in self.evidence_event_ids):
            raise ValueError("TRAJECTORY_EVENT_ID_INVALID: event IDs must be positive")
        if len(self.evidence_event_ids) != len(set(self.evidence_event_ids)):
            raise ValueError("TRAJECTORY_DUPLICATE_EVENT: event IDs must be unique")
        return self

    @property
    def has_signal(self) -> bool:
        return (
            self.goal_similarity < 0.8
            or self.denied_scope_attempts > 0
            or self.unplanned_tool_calls > 0
            or self.injection_indicators > 0
            or self.credential_access_attempts > 0
            or self.classification_escalations > 0
            or self.retry_count >= 3
            or self.sensitive_read_then_egress
            or self.denial_bypass_attempts > 0
            or self.repeated_operation_count >= 3
            or self.scope_escalations > 0
            or self.untrusted_write_attempts > 0
            or self.unresolved_candidates > 0
        )


class TrajectoryMonitor:
    def evaluate(self, snapshot: TrajectorySnapshot) -> TrajectoryDecision:
        if snapshot.has_signal and not snapshot.evidence_event_ids:
            raise PlatformError(
                "TRAJECTORY_EVIDENCE_REQUIRED",
                "TRAJECTORY_EVIDENCE_REQUIRED: control signals need immutable event evidence",
            )
        evidence = list(snapshot.evidence_event_ids)

        if snapshot.sensitive_read_then_egress:
            return TrajectoryDecision(
                action=TrajectoryAction.TERMINATE,
                risk_score=1.0,
                reason_codes=["SENSITIVE_READ_THEN_EGRESS"],
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_incident_review",
                evidence_event_ids=evidence,
            )
        if snapshot.credential_access_attempts:
            return TrajectoryDecision(
                action=TrajectoryAction.TERMINATE,
                risk_score=0.98,
                reason_codes=["CREDENTIAL_ACCESS_ATTEMPT"],
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_incident_review",
                evidence_event_ids=evidence,
            )
        if snapshot.untrusted_write_attempts:
            return TrajectoryDecision(
                action=TrajectoryAction.TERMINATE,
                risk_score=0.98,
                reason_codes=["UNTRUSTED_CONTENT_WRITE_ATTEMPT"],
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_incident_review",
                evidence_event_ids=evidence,
            )
        if snapshot.unresolved_candidates:
            return TrajectoryDecision(
                action=TrajectoryAction.PAUSE,
                risk_score=0.95,
                reason_codes=["INCOMPLETE_TRAJECTORY_PREFLIGHT"],
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_review",
                evidence_event_ids=evidence,
            )
        if snapshot.denial_bypass_attempts:
            return TrajectoryDecision(
                action=TrajectoryAction.PAUSE,
                risk_score=0.94,
                reason_codes=["DENIAL_BYPASS_ATTEMPT"],
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_review",
                evidence_event_ids=evidence,
            )
        if (
            snapshot.injection_indicators >= 2
            or snapshot.classification_escalations >= 2
            or snapshot.scope_escalations >= 2
            or snapshot.repeated_operation_count >= 3
        ):
            reasons: list[str] = []
            if snapshot.injection_indicators >= 2:
                reasons.append("REPEATED_PROMPT_INJECTION")
            if snapshot.classification_escalations >= 2:
                reasons.append("DATA_CLASSIFICATION_ESCALATION")
            if snapshot.scope_escalations >= 2:
                reasons.append("REPEATED_SCOPE_ESCALATION")
            if snapshot.repeated_operation_count >= 3:
                reasons.append("REPEATED_OPERATION_LOOP")
            return TrajectoryDecision(
                action=TrajectoryAction.PAUSE,
                risk_score=0.9,
                reason_codes=reasons,
                disabled_capabilities=snapshot.candidate_capabilities,
                required_approval="security_review",
                evidence_event_ids=evidence,
            )
        if (
            snapshot.denied_scope_attempts >= 2
            or snapshot.unplanned_tool_calls
            or snapshot.scope_escalations
        ):
            reasons = []
            if snapshot.denied_scope_attempts >= 2:
                reasons.append("REPEATED_SCOPE_PROBING")
            if snapshot.unplanned_tool_calls:
                reasons.append("UNPLANNED_TOOL_CHAIN")
            if snapshot.scope_escalations:
                reasons.append("SCOPE_ESCALATION")
            disabled = snapshot.candidate_capabilities or frozenset({"unplanned_tools"})
            return TrajectoryDecision(
                action=TrajectoryAction.RESTRICT,
                risk_score=0.7,
                reason_codes=reasons,
                disabled_capabilities=disabled,
                evidence_event_ids=evidence,
            )
        if (
            snapshot.goal_similarity < 0.8
            or snapshot.retry_count >= 3
            or snapshot.injection_indicators
            or snapshot.classification_escalations
            or snapshot.denied_scope_attempts
        ):
            reasons = []
            if snapshot.goal_similarity < 0.8:
                reasons.append("GOAL_DRIFT_WARNING")
            if snapshot.retry_count >= 3:
                reasons.append("RETRY_ANOMALY")
            if snapshot.injection_indicators:
                reasons.append("PROMPT_INJECTION_INDICATOR")
            if snapshot.classification_escalations:
                reasons.append("CLASSIFICATION_CHANGE")
            if snapshot.denied_scope_attempts:
                reasons.append("SCOPE_DENIAL")
            return TrajectoryDecision(
                action=TrajectoryAction.WARN,
                risk_score=0.45,
                reason_codes=reasons,
                evidence_event_ids=evidence,
            )
        return TrajectoryDecision(
            action=TrajectoryAction.CONTINUE,
            risk_score=min(0.2, 1 - snapshot.goal_similarity),
            reason_codes=[],
            evidence_event_ids=[],
        )


class TrajectoryCandidate(BaseModel):
    """Minimized preflight facts; raw model input and tool arguments are never persisted."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    boundary: Literal["model", "tool", "prepare", "commit"]
    task_id: str = Field(min_length=1, max_length=256)
    plan_version: int = Field(default=0, ge=0, le=10_000)
    operation_name: str = Field(min_length=1, max_length=256)
    capability: str | None = Field(default=None, min_length=1, max_length=256)
    args_hash: str = Field(min_length=1, max_length=256)
    data_scope_hash: str | None = Field(default=None, min_length=1, max_length=256)
    planned: bool = True
    scope_escalation: bool = False
    injection_indicators: int = Field(default=0, ge=0, le=100)
    content_signal_hash: str | None = Field(default=None, min_length=1, max_length=256)
    credential_access_attempts: int = Field(default=0, ge=0, le=100)
    classification_escalation: bool = False
    retry_count: int = Field(default=0, ge=0, le=10_000)
    sensitive_data_egress: bool = False
    principal_id: str | None = Field(default=None, min_length=1, max_length=256)
    principal_scopes: frozenset[str] | None = Field(default=None, exclude=True)
    requested_data_scope: Mapping[str, Any] | None = Field(default=None, exclude=True)
    action_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TrajectoryCheck:
    run_id: UUID
    tenant_id: str
    candidate_id: UUID
    candidate: TrajectoryCandidate
    correlation_id: str
    actor_type: str
    actor_id: str | None
    candidate_payload: Mapping[str, Any]
    effective_disabled_capabilities: frozenset[str]


@dataclass(frozen=True, slots=True)
class TrajectoryProjection:
    snapshot: TrajectorySnapshot
    disabled_capabilities: frozenset[str]
    disabled_evidence_event_ids: tuple[int, ...]


class TrajectoryProjector:
    """Rebuild all safety signals exclusively from immutable Run events."""

    def project(
        self,
        run: RunRecord,
        events: Sequence[EventRecord],
        *,
        current_candidate_id: UUID,
    ) -> TrajectoryProjection:
        del run
        candidates: dict[str, EventRecord] = {}
        decisions: dict[str, EventRecord] = {}
        outcomes: list[EventRecord] = []
        disabled: set[str] = set()
        disabled_evidence: set[int] = set()
        malformed_evidence: set[int] = set()

        for event in events:
            candidate_id = event.payload.get("candidate_id")
            if event.event_type == "trajectory.candidate":
                if isinstance(candidate_id, str) and candidate_id:
                    candidates[candidate_id] = event
                else:
                    malformed_evidence.add(event.sequence_no)
            elif event.event_type == "trajectory.decision":
                if isinstance(candidate_id, str) and candidate_id:
                    decisions[candidate_id] = event
                else:
                    malformed_evidence.add(event.sequence_no)
                raw_disabled = event.payload.get("disabled_capabilities", ())
                if isinstance(raw_disabled, list):
                    for capability in raw_disabled:
                        if isinstance(capability, str) and capability:
                            disabled.add(capability)
                            disabled_evidence.add(event.sequence_no)
            elif event.event_type == "trajectory.outcome":
                outcomes.append(event)

        current_id = str(current_candidate_id)
        current_event = candidates.get(current_id)
        if current_event is None:
            raise PlatformError(
                "TRAJECTORY_CANDIDATE_EVIDENCE_MISSING",
                "The current preflight candidate was not persisted",
            )
        current = current_event.payload
        unresolved = [
            event
            for candidate_id, event in candidates.items()
            if candidate_id != current_id and candidate_id not in decisions
        ]

        evidence: set[int] = set(malformed_evidence)
        evidence.update(event.sequence_no for event in unresolved)
        denied_scope = 0
        denied_outcomes: list[EventRecord] = []
        prior_untrusted_outputs: list[EventRecord] = []
        for event in outcomes:
            status = event.payload.get("status")
            denial_kind = event.payload.get("denial_kind")
            if status == "denied" and denial_kind in {"scope", "policy"}:
                denied_scope += 1
                denied_outcomes.append(event)
                evidence.add(event.sequence_no)
            if status == "succeeded" and event.payload.get("produced_untrusted_content") is True:
                prior_untrusted_outputs.append(event)

        unplanned_events = [
            event
            for event in candidates.values()
            if event.payload.get("boundary") in {"tool", "prepare", "commit"}
            and event.payload.get("planned") is False
        ]
        scope_events = [
            event for event in candidates.values() if event.payload.get("scope_escalation") is True
        ]
        classification_events = [
            event
            for event in candidates.values()
            if event.payload.get("classification_escalation") is True
        ]
        evidence.update(event.sequence_no for event in unplanned_events)
        evidence.update(event.sequence_no for event in scope_events)
        evidence.update(event.sequence_no for event in classification_events)

        signal_hashes: set[str] = set()
        injection_count = 0
        credential_count = 0
        retry_count = 0
        for event in candidates.values():
            raw_indicators = event.payload.get("injection_indicators", 0)
            indicators = raw_indicators if isinstance(raw_indicators, int) else 0
            signal_hash = event.payload.get("content_signal_hash")
            if indicators > 0 and (
                not isinstance(signal_hash, str) or signal_hash not in signal_hashes
            ):
                injection_count += indicators
                evidence.add(event.sequence_no)
                if isinstance(signal_hash, str):
                    signal_hashes.add(signal_hash)
            raw_credentials = event.payload.get("credential_access_attempts", 0)
            if isinstance(raw_credentials, int) and raw_credentials > 0:
                credential_count += raw_credentials
                evidence.add(event.sequence_no)
            raw_retry = event.payload.get("retry_count", 0)
            if isinstance(raw_retry, int):
                retry_count = max(retry_count, raw_retry)

        current_fingerprint = self._fingerprint(current)
        repeated_events = [
            event
            for event in candidates.values()
            if self._fingerprint(event.payload) == current_fingerprint
        ]
        repeated_count = len(repeated_events)
        if repeated_count >= 3:
            evidence.update(event.sequence_no for event in repeated_events)

        denial_bypass = 0
        latest_denial = next(
            (
                event
                for event in reversed(denied_outcomes)
                if event.sequence_no < current_event.sequence_no
                and event.payload.get("task_id") == current.get("task_id")
            ),
            None,
        )
        if latest_denial is not None and self._bypass_changed(latest_denial.payload, current):
            denial_bypass = 1
            evidence.update({latest_denial.sequence_no, current_event.sequence_no})

        untrusted_write = 0
        if (
            current.get("boundary") in {"prepare", "commit"}
            and isinstance(current.get("injection_indicators"), int)
            and current["injection_indicators"] > 0
            and any(
                event.sequence_no < current_event.sequence_no for event in prior_untrusted_outputs
            )
        ):
            untrusted_write = 1
            evidence.add(current_event.sequence_no)
            evidence.update(
                event.sequence_no
                for event in prior_untrusted_outputs
                if event.sequence_no < current_event.sequence_no
            )

        sensitive_egress_events = [
            event
            for event in candidates.values()
            if event.payload.get("sensitive_data_egress") is True
            and any(outcome.sequence_no < event.sequence_no for outcome in prior_untrusted_outputs)
        ]
        evidence.update(event.sequence_no for event in sensitive_egress_events)
        if sensitive_egress_events:
            evidence.update(
                event.sequence_no
                for event in prior_untrusted_outputs
                if event.sequence_no < sensitive_egress_events[-1].sequence_no
            )

        offending_capabilities: set[str] = set()
        for event in [*unplanned_events, *scope_events, *denied_outcomes]:
            capability = event.payload.get("capability")
            if isinstance(capability, str) and capability:
                offending_capabilities.add(capability)
        if denial_bypass or repeated_count >= 3 or untrusted_write:
            capability = current.get("capability")
            if isinstance(capability, str) and capability:
                offending_capabilities.add(capability)

        snapshot = TrajectorySnapshot(
            goal_similarity=1.0,
            denied_scope_attempts=denied_scope,
            unplanned_tool_calls=len(unplanned_events),
            injection_indicators=injection_count,
            credential_access_attempts=credential_count,
            classification_escalations=len(classification_events),
            retry_count=retry_count,
            sensitive_read_then_egress=bool(sensitive_egress_events),
            denial_bypass_attempts=denial_bypass,
            repeated_operation_count=repeated_count,
            scope_escalations=len(scope_events),
            untrusted_write_attempts=untrusted_write,
            unresolved_candidates=len(unresolved) + len(malformed_evidence),
            candidate_capabilities=frozenset(offending_capabilities),
            evidence_event_ids=tuple(sorted(evidence)),
        )
        return TrajectoryProjection(
            snapshot=snapshot,
            disabled_capabilities=frozenset(disabled),
            disabled_evidence_event_ids=tuple(sorted(disabled_evidence)),
        )

    @staticmethod
    def _fingerprint(payload: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            payload.get("boundary"),
            payload.get("task_id"),
            payload.get("operation_name"),
            payload.get("capability"),
            payload.get("args_hash"),
            payload.get("data_scope_hash"),
        )

    @staticmethod
    def _bypass_changed(
        denied: Mapping[str, Any],
        current: Mapping[str, Any],
    ) -> bool:
        fields = ("operation_name", "capability", "args_hash", "data_scope_hash")
        return any(denied.get(field) != current.get(field) for field in fields)


class TrajectoryGuard:
    """Fail-closed production guard backed only by the Run repository and events."""

    def __init__(
        self,
        runs: Any,
        *,
        monitor: TrajectoryMonitor | None = None,
        projector: TrajectoryProjector | None = None,
        kill_switches: Any | None = None,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self._runs = runs
        self._monitor = monitor or TrajectoryMonitor()
        self._projector = projector or TrajectoryProjector()
        self._kill_switches = kill_switches
        self._observability = observability

    async def preflight(
        self,
        *,
        run_id: UUID,
        tenant_id: str,
        candidate: TrajectoryCandidate,
        correlation_id: str,
        actor_type: str = "trajectory-monitor",
        actor_id: str | None = None,
    ) -> TrajectoryCheck:
        preliminary = await self._runs.get(run_id, tenant_id)
        self._ensure_active(preliminary)
        await self._require_kill_switch_allowed(preliminary, candidate)

        candidate_id = uuid4()
        decision: TrajectoryDecision
        effective_disabled: frozenset[str]
        async with self._runs.trajectory_transaction(run_id, tenant_id) as transaction:
            run = transaction.run
            self._ensure_active(run)
            normalized = self._candidate_payload(run, candidate, candidate_id)
            candidate_event = await transaction.append_event(
                AuditEvent(
                    event_type="trajectory.candidate",
                    payload=normalized,
                    correlation_id=correlation_id,
                    actor_type=actor_type,
                    actor_id=actor_id or run.principal_id,
                    task_id=candidate.task_id,
                    action_id=candidate.action_id,
                )
            )
            projection = self._projector.project(
                run,
                transaction.events,
                current_candidate_id=candidate_id,
            )
            decision = self._monitor.evaluate(projection.snapshot)
            if (
                candidate.capability is not None
                and candidate.capability in projection.disabled_capabilities
            ):
                evidence = sorted(
                    {
                        candidate_event.sequence_no,
                        *projection.disabled_evidence_event_ids,
                    }
                )
                decision = TrajectoryDecision(
                    action=TrajectoryAction.RESTRICT,
                    risk_score=max(decision.risk_score, 0.8),
                    reason_codes=["CAPABILITY_RESTRICTED_BY_TRAJECTORY"],
                    disabled_capabilities={candidate.capability},
                    evidence_event_ids=evidence,
                )
            effective_disabled = frozenset(
                projection.disabled_capabilities | decision.disabled_capabilities
            )
            previous_status = run.status
            if decision.action is TrajectoryAction.PAUSE:
                run.paused_from = previous_status
                run.status = RunStatus.PAUSED
                run.pause_requested = True
                run.updated_at = datetime.now(UTC)
                await transaction.save_run(run.version)
            elif decision.action is TrajectoryAction.TERMINATE:
                run.status = RunStatus.FAILED
                run.failure_code = "TRAJECTORY_TERMINATED"
                run.pause_requested = False
                run.updated_at = datetime.now(UTC)
                run.completed_at = run.updated_at
                await transaction.save_run(run.version)
            await transaction.append_event(
                AuditEvent(
                    event_type="trajectory.decision",
                    payload={
                        "candidate_id": str(candidate_id),
                        "candidate_event_id": candidate_event.event_id,
                        "candidate_sequence_no": candidate_event.sequence_no,
                        "action": decision.action.value,
                        "risk_score": decision.risk_score,
                        "reason_codes": list(decision.reason_codes),
                        "disabled_capabilities": sorted(decision.disabled_capabilities),
                        "effective_disabled_capabilities": sorted(effective_disabled),
                        "required_approval": decision.required_approval,
                        "evidence_event_ids": list(decision.evidence_event_ids),
                        "run_status": run.status.value,
                        "paused_from": (
                            previous_status.value
                            if decision.action is TrajectoryAction.PAUSE
                            else None
                        ),
                    },
                    correlation_id=correlation_id,
                    actor_type=actor_type,
                    actor_id=actor_id or run.principal_id,
                    task_id=candidate.task_id,
                    action_id=candidate.action_id,
                )
            )

        self._observe(decision)
        if decision.action is TrajectoryAction.PAUSE:
            raise PlatformError(
                "TRAJECTORY_PAUSED",
                "Whole-run trajectory controls paused the Run before execution",
                http_status=409,
                context={"reason_codes": list(decision.reason_codes)},
            )
        if decision.action is TrajectoryAction.TERMINATE:
            raise PlatformError(
                "TRAJECTORY_TERMINATED",
                "Whole-run trajectory controls terminated the Run before execution",
                http_status=409,
                context={"reason_codes": list(decision.reason_codes)},
            )
        if candidate.capability is not None and candidate.capability in effective_disabled:
            raise PlatformError(
                "TRAJECTORY_RESTRICTED",
                "The candidate capability was disabled by whole-run trajectory controls",
                http_status=403,
                context={
                    "capability": candidate.capability,
                    "reason_codes": list(decision.reason_codes),
                },
            )
        return TrajectoryCheck(
            run_id=run_id,
            tenant_id=tenant_id,
            candidate_id=candidate_id,
            candidate=candidate,
            correlation_id=correlation_id,
            actor_type=actor_type,
            actor_id=actor_id,
            candidate_payload=dict(normalized),
            effective_disabled_capabilities=effective_disabled,
        )

    def outcome_event(
        self,
        check: TrajectoryCheck,
        *,
        status: Literal["succeeded", "denied", "failed"],
        error_code: str | None = None,
        denial_kind: Literal["scope", "policy", "validation", "operational", "other"] | None = None,
        produced_untrusted_content: bool = False,
    ) -> AuditEvent:
        if status == "denied" and (error_code is None or denial_kind is None):
            raise ValueError("TRAJECTORY_DENIAL_CONTEXT_REQUIRED")
        if status != "denied" and denial_kind is not None:
            raise ValueError("TRAJECTORY_DENIAL_KIND_STATUS_MISMATCH")
        candidate = check.candidate
        persisted = check.candidate_payload
        return AuditEvent(
            event_type="trajectory.outcome",
            payload={
                "candidate_id": str(check.candidate_id),
                "boundary": persisted.get("boundary"),
                "task_id": persisted.get("task_id"),
                "plan_version": persisted.get("plan_version"),
                "operation_name": persisted.get("operation_name"),
                "capability": persisted.get("capability"),
                "args_hash": persisted.get("args_hash"),
                "data_scope_hash": persisted.get("data_scope_hash"),
                "status": status,
                "error_code": error_code,
                "denial_kind": denial_kind,
                "produced_untrusted_content": produced_untrusted_content,
            },
            correlation_id=check.correlation_id,
            actor_type=check.actor_type,
            actor_id=check.actor_id,
            task_id=candidate.task_id,
            action_id=candidate.action_id,
        )

    async def record_outcome(
        self,
        check: TrajectoryCheck,
        *,
        status: Literal["succeeded", "denied", "failed"],
        error_code: str | None = None,
        denial_kind: Literal["scope", "policy", "validation", "operational", "other"] | None = None,
        produced_untrusted_content: bool = False,
    ) -> None:
        if status == "denied" and (error_code is None or denial_kind is None):
            raise ValueError("TRAJECTORY_DENIAL_CONTEXT_REQUIRED")
        if status != "denied" and denial_kind is not None:
            raise ValueError("TRAJECTORY_DENIAL_KIND_STATUS_MISMATCH")
        async with self._runs.trajectory_transaction(
            check.run_id,
            check.tenant_id,
        ) as transaction:
            existing = next(
                (
                    event
                    for event in transaction.events
                    if event.event_type == "trajectory.outcome"
                    and event.payload.get("candidate_id") == str(check.candidate_id)
                ),
                None,
            )
            if existing is not None:
                if existing.payload.get("status") != status:
                    raise PlatformError(
                        "TRAJECTORY_OUTCOME_CONFLICT",
                        "A preflight candidate already has a different durable outcome",
                    )
                return
            has_decision = any(
                event.event_type == "trajectory.decision"
                and event.payload.get("candidate_id") == str(check.candidate_id)
                for event in transaction.events
            )
            candidate_event = next(
                (
                    event
                    for event in transaction.events
                    if event.event_type == "trajectory.candidate"
                    and event.payload.get("candidate_id") == str(check.candidate_id)
                ),
                None,
            )
            if not has_decision or candidate_event is None:
                raise PlatformError(
                    "TRAJECTORY_DECISION_EVIDENCE_MISSING",
                    "A candidate outcome cannot be recorded without its durable decision",
                )
            candidate = check.candidate
            candidate_payload = candidate_event.payload
            await transaction.append_event(
                AuditEvent(
                    event_type="trajectory.outcome",
                    payload={
                        "candidate_id": str(check.candidate_id),
                        "boundary": candidate_payload.get("boundary"),
                        "task_id": candidate_payload.get("task_id"),
                        "plan_version": candidate_payload.get("plan_version"),
                        "operation_name": candidate_payload.get("operation_name"),
                        "capability": candidate_payload.get("capability"),
                        "args_hash": candidate_payload.get("args_hash"),
                        "data_scope_hash": candidate_payload.get("data_scope_hash"),
                        "status": status,
                        "error_code": error_code,
                        "denial_kind": denial_kind,
                        "produced_untrusted_content": produced_untrusted_content,
                    },
                    correlation_id=check.correlation_id,
                    actor_type=check.actor_type,
                    actor_id=check.actor_id or transaction.run.principal_id,
                    task_id=candidate.task_id,
                    action_id=candidate.action_id,
                )
            )

    @staticmethod
    def _candidate_payload(
        run: RunRecord,
        candidate: TrajectoryCandidate,
        candidate_id: UUID,
    ) -> dict[str, Any]:
        contract = run.contract
        allowed_capabilities = frozenset(getattr(contract, "allowed_capabilities", frozenset()))
        planned = candidate.planned
        if candidate.capability is not None and candidate.boundary != "model":
            planned = candidate.capability in allowed_capabilities

        scope_escalation = candidate.scope_escalation
        contract_principal = getattr(contract, "principal", None)
        if candidate.principal_id is not None and contract_principal is not None:
            scope_escalation = scope_escalation or (
                candidate.principal_id != getattr(contract_principal, "user_id", None)
            )
        if candidate.principal_scopes is not None and contract_principal is not None:
            authoritative_scopes = frozenset(getattr(contract_principal, "scopes", frozenset()))
            scope_escalation = scope_escalation or not (
                candidate.principal_scopes <= authoritative_scopes
            )

        authoritative_scope = getattr(contract, "data_scope", None)
        requested_scope: DataScope | None = None
        if candidate.requested_data_scope is not None:
            try:
                requested_scope = DataScope.model_validate(candidate.requested_data_scope)
            except ValueError:
                scope_escalation = True
            if requested_scope is not None and isinstance(authoritative_scope, DataScope):
                scope_escalation = scope_escalation or not requested_scope.is_subset_of(
                    authoritative_scope
                )
        effective_scope = requested_scope or authoritative_scope
        effective_scope_hash = candidate.data_scope_hash
        if effective_scope is not None:
            effective_scope_hash = payload_hash(effective_scope)

        write_policy = getattr(contract, "external_write_policy", "deny")
        if candidate.boundary == "prepare" and write_policy == "deny":
            planned = False
        if candidate.boundary == "commit" and write_policy != "approval":
            planned = False

        return {
            "candidate_id": str(candidate_id),
            "boundary": candidate.boundary,
            "task_id": candidate.task_id,
            "plan_version": candidate.plan_version,
            "operation_name": candidate.operation_name,
            "capability": candidate.capability,
            "args_hash": candidate.args_hash,
            "data_scope_hash": effective_scope_hash or "scope-unavailable",
            "planned": planned,
            "scope_escalation": scope_escalation,
            "injection_indicators": candidate.injection_indicators,
            "content_signal_hash": candidate.content_signal_hash,
            "credential_access_attempts": candidate.credential_access_attempts,
            "classification_escalation": candidate.classification_escalation,
            "retry_count": candidate.retry_count,
            "sensitive_data_egress": candidate.sensitive_data_egress,
            "action_id": str(candidate.action_id) if candidate.action_id is not None else None,
        }

    @staticmethod
    def _ensure_active(run: RunRecord) -> None:
        if run.cancellation_requested or run.status is RunStatus.CANCELLED:
            raise PlatformError(
                "RUN_CANCELLED",
                "The Run was cancelled before the next execution boundary",
                http_status=409,
            )
        if run.pause_requested or run.status is RunStatus.PAUSED:
            raise PlatformError(
                "TRAJECTORY_RUN_PAUSED",
                "The Run is paused; no new execution boundary may start",
                http_status=409,
            )
        if run.status in {RunStatus.COMPLETED, RunStatus.FAILED}:
            raise PlatformError(
                "TRAJECTORY_RUN_TERMINAL",
                "A terminal Run cannot start a new execution boundary",
                http_status=409,
                context={"status": run.status.value},
            )

    async def _require_kill_switch_allowed(
        self,
        run: RunRecord,
        candidate: TrajectoryCandidate,
    ) -> None:
        if self._kill_switches is None:
            return
        constraints = getattr(run.contract, "constraints", {})
        configured = constraints.get("use_case") if isinstance(constraints, dict) else None
        requested_output = getattr(run.contract, "requested_output", None)
        fallback = getattr(requested_output, "schema_name", "agent.run")
        use_case = configured if isinstance(configured, str) and configured.strip() else fallback
        operation = "read" if candidate.boundary == "tool" else candidate.boundary
        await self._kill_switches.require_allowed(
            tenant_id=run.tenant_id,
            use_case=use_case,
            capability=candidate.capability or f"model.{candidate.operation_name}",
            operation=operation,
        )

    def _observe(self, decision: TrajectoryDecision) -> None:
        if self._observability is None or decision.action is TrajectoryAction.CONTINUE:
            return
        severity = {
            TrajectoryAction.WARN: "warning",
            TrajectoryAction.RESTRICT: "warning",
            TrajectoryAction.PAUSE: "critical",
            TrajectoryAction.TERMINATE: "critical",
        }[decision.action]
        for reason in decision.reason_codes:
            self._observability.record_trajectory_alert(
                severity=severity,
                reason=reason,
            )
            self._observability.record_security_event(
                category=reason,
                severity="sev2" if severity == "critical" else "sev3",
                outcome="blocked",
            )


@dataclass(frozen=True, slots=True)
class TrajectoryContentSignals:
    injection_indicators: int
    content_signal_hash: str | None
    credential_access_attempts: int


_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"(?:system|developer)\s+(?:prompt|instructions?)", re.IGNORECASE),
    re.compile(r"(?:administrator|admin)\s+(?:authorization|instruction|rule)", re.IGNORECASE),
    re.compile(r"(?:upload|send|export|exfiltrat\w*)\b.{0,80}\bexternal", re.IGNORECASE),
    re.compile(r"(?:call|invoke|use)\b.{0,80}\b(?:tool|capability|\.prepare)", re.IGNORECASE),
    re.compile(r"(?:permanent|long[- ]term)\b.{0,80}\b(?:memory|instruction|rule)", re.IGNORECASE),
)
_CREDENTIAL_PATTERN = re.compile(
    r"\b(?:api[-_ ]?key|access[-_ ]?token|password|credential|secret)\b",
    re.IGNORECASE,
)


def inspect_trajectory_content(value: Any) -> TrajectoryContentSignals:
    """Return minimized deterministic signals without retaining the inspected content."""
    matches: list[str] = []
    matched_content_hashes: list[str] = []
    credential_matches = 0
    for text in _string_values(value):
        text_matched = False
        for index, pattern in enumerate(_INJECTION_PATTERNS):
            if pattern.search(text):
                matches.append(f"injection-{index}")
                text_matched = True
        if text_matched:
            matched_content_hashes.append(hashlib.sha256(text.encode("utf-8")).hexdigest())
        credential_matches += len(_CREDENTIAL_PATTERN.findall(text))
    unique_matches = sorted(set(matches))
    digest_material = [*unique_matches, *sorted(set(matched_content_hashes))]
    digest = (
        hashlib.sha256("|".join(digest_material).encode("utf-8")).hexdigest()
        if unique_matches
        else None
    )
    return TrajectoryContentSignals(
        injection_indicators=len(unique_matches),
        content_signal_hash=digest,
        credential_access_attempts=min(credential_matches, 100),
    )


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        values: list[str] = []
        for key, item in value.items():
            values.extend(_string_values(str(key)))
            values.extend(_string_values(item))
        return values
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        values = []
        for item in value:
            values.extend(_string_values(item))
        return values
    return []
