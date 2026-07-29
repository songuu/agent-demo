from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any
from uuid import UUID, uuid4

from agent_platform.application.errors import (
    Conflict,
    Forbidden,
    StaleActionHash,
    UnknownOutcome,
)
from agent_platform.application.records import (
    ActionAuditTransaction,
    ActionRecord,
    AuditEvent,
    ToolInvocationRecord,
)
from agent_platform.application.trajectory_monitor import (
    TrajectoryCandidate,
    TrajectoryCheck,
    inspect_trajectory_content,
)
from agent_platform.domain.enums import ActionStatus, ToolEffect
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.state_machines import ensure_action_transition
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


class CommitService:
    """The only service allowed to produce external side effects."""

    def __init__(
        self,
        actions: Any,
        runs: Any,
        registry: Any,
        policy: Any,
        credentials: Any,
        *,
        kill_switches: Any | None = None,
        trajectory_guard: Any | None = None,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self._actions = actions
        self._runs = runs
        self._registry = registry
        self._policy = policy
        self._credentials = credentials
        self._kill_switches = kill_switches
        self._trajectory = trajectory_guard
        self._observability = observability

    async def commit(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        principal_scopes: frozenset[str],
        action_id: UUID,
        correlation_id: str,
    ) -> Any:

        receipt: Any = None
        trajectory: TrajectoryCheck | None = None
        guard = self._trajectory
        async with self._actions.transaction(action_id, tenant_id) as transaction:
            action = transaction.action
            if action.status == ActionStatus.COMMITTED:
                return action.receipt
            if action.status == ActionStatus.UNKNOWN:
                raise UnknownOutcome(str(action_id))
            if action.status != ActionStatus.APPROVED:
                raise Conflict(
                    "INVALID_STATE_TRANSITION",
                    "Only an approved action may be committed",
                    action_id=str(action_id),
                    status=action.status.value,
                )
            await self._require_commit_allowed(action)
            trajectory = await self._trajectory_preflight_commit(
                action,
                principal_id=principal_id,
                principal_scopes=principal_scopes,
                correlation_id=correlation_id,
            )
            if action.expires_at <= datetime.now(UTC):
                ensure_action_transition(
                    action.status,
                    ActionStatus.EXPIRED,
                    action_id=str(action_id),
                )
                action.status = ActionStatus.EXPIRED
                transaction.append_event(
                    AuditEvent(
                        event_type="action.expired",
                        payload={
                            "action_id": str(action.action_id),
                            "payload_hash": action.payload_hash,
                            "policy_version": action.policy_version,
                            "status": action.status.value,
                        },
                        correlation_id=correlation_id,
                        actor_type="commit-worker",
                        actor_id=principal_id,
                        action_id=action.action_id,
                    )
                )
                raise Conflict("ACTION_EXPIRED", "Action approval expired before commit")
            if payload_hash(action.canonical_payload) != action.payload_hash:
                raise StaleActionHash(str(action_id))

            decision = await self._policy.authorize_action(
                self._policy_request(
                    action,
                    tenant_id=tenant_id,
                    principal_id=principal_id,
                    principal_scopes=principal_scopes,
                    phase="commit",
                )
            )
            self._record_policy("commit", decision.allowed, decision.reason_codes)
            if not decision.allowed:
                if trajectory is not None and guard is not None:
                    transaction.append_event(
                        guard.outcome_event(
                            trajectory,
                            status="denied",
                            error_code="ACTION_COMMIT_DENIED",
                            denial_kind="policy",
                        )
                    )
                transaction.append_event(
                    AuditEvent(
                        event_type="action.commit_denied",
                        payload={
                            "action_id": str(action.action_id),
                            "payload_hash": action.payload_hash,
                            "policy_decision_id": self._policy_decision_id(action, decision),
                            "policy_version": decision.policy_version,
                            "reason_codes": list(decision.reason_codes),
                        },
                        correlation_id=correlation_id,
                        actor_type="commit-worker",
                        actor_id=principal_id,
                        action_id=action.action_id,
                    )
                )
                raise Forbidden(
                    "ACTION_COMMIT_DENIED",
                    f"Commit reauthorization denied: {','.join(decision.reason_codes)}",
                )
            tool = await self._registry.resolve_exact(
                action.tool_name, action.tool_version, tenant_id
            )
            credential = await self._credentials.issue(
                tenant_id,
                principal_id,
                principal_scopes
                & self._commit_scopes(tool.definition)
                & decision.credential_scopes,
                ttl_seconds=min(tool.definition.timeout_seconds + 5, 300),
            )
            tool_started = monotonic()
            existing = await tool.adapter.lookup_by_idempotency_key(
                action.idempotency_key, credential
            )
            if existing is None:
                ensure_action_transition(
                    action.status, ActionStatus.COMMITTING, action_id=str(action_id)
                )
                action.status = ActionStatus.COMMITTING
                try:
                    async with asyncio.timeout(tool.definition.timeout_seconds):
                        receipt = await tool.adapter.commit(
                            action.canonical_payload,
                            credential,
                            action.idempotency_key,
                        )
                except TimeoutError as exc:
                    unknown = UnknownOutcome(str(action_id))
                    ensure_action_transition(
                        action.status, ActionStatus.UNKNOWN, action_id=str(action_id)
                    )
                    action.status = ActionStatus.UNKNOWN
                    action.failure_code = unknown.code
                    self._record_action(action, ActionStatus.UNKNOWN)
                    self._record_tool(
                        action.tool_name,
                        action.tool_version,
                        "commit",
                        "unknown",
                        monotonic() - tool_started,
                    )
                    self._stage_commit_audit(
                        transaction,
                        action,
                        decision=decision,
                        trajectory=trajectory,
                        principal_id=principal_id,
                        correlation_id=correlation_id,
                        status="unknown",
                        duration_seconds=monotonic() - tool_started,
                        receipt=receipt,
                        verification=None,
                        error_code=action.failure_code,
                    )
                    raise unknown from exc
                except UnknownOutcome as exc:
                    ensure_action_transition(
                        action.status, ActionStatus.UNKNOWN, action_id=str(action_id)
                    )
                    action.status = ActionStatus.UNKNOWN
                    action.failure_code = exc.code
                    self._record_action(action, ActionStatus.UNKNOWN)
                    self._record_tool(
                        action.tool_name,
                        action.tool_version,
                        "commit",
                        "unknown",
                        monotonic() - tool_started,
                    )
                    self._stage_commit_audit(
                        transaction,
                        action,
                        decision=decision,
                        trajectory=trajectory,
                        principal_id=principal_id,
                        correlation_id=correlation_id,
                        status="unknown",
                        duration_seconds=monotonic() - tool_started,
                        receipt=receipt,
                        verification=None,
                        error_code=action.failure_code,
                    )
                    raise
                except Exception as exc:
                    # A provider exception may happen after it accepted the request.
                    # Treat the result as unknown and reconcile by idempotency key.
                    unknown = UnknownOutcome(str(action_id))
                    ensure_action_transition(
                        action.status, ActionStatus.UNKNOWN, action_id=str(action_id)
                    )
                    action.status = ActionStatus.UNKNOWN
                    action.failure_code = unknown.code
                    self._record_action(action, ActionStatus.UNKNOWN)
                    self._record_tool(
                        action.tool_name,
                        action.tool_version,
                        "commit",
                        "unknown",
                        monotonic() - tool_started,
                    )
                    self._stage_commit_audit(
                        transaction,
                        action,
                        decision=decision,
                        trajectory=trajectory,
                        principal_id=principal_id,
                        correlation_id=correlation_id,
                        status="unknown",
                        duration_seconds=monotonic() - tool_started,
                        receipt=receipt,
                        verification=None,
                        error_code=action.failure_code,
                    )
                    raise unknown from exc
            else:
                receipt = existing

            try:
                verification = await tool.adapter.verify(action, receipt, credential)
            except Exception as exc:
                # The side effect returned a receipt, but its external state could
                # not be read. Persist enough evidence for safe reconciliation.
                if action.status == ActionStatus.APPROVED:
                    ensure_action_transition(
                        action.status, ActionStatus.COMMITTING, action_id=str(action_id)
                    )
                    action.status = ActionStatus.COMMITTING
                ensure_action_transition(
                    action.status, ActionStatus.UNKNOWN, action_id=str(action_id)
                )
                action.status = ActionStatus.UNKNOWN
                action.failure_code = "SIDE_EFFECT_VERIFICATION_UNKNOWN"
                action.receipt = receipt
                action.verification = None
                self._record_action(action, ActionStatus.UNKNOWN)
                self._record_verification_failure(
                    "side_effect",
                    "SIDE_EFFECT_VERIFICATION_UNKNOWN",
                )
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "commit",
                    "unknown",
                    monotonic() - tool_started,
                )
                self._stage_commit_audit(
                    transaction,
                    action,
                    decision=decision,
                    trajectory=trajectory,
                    principal_id=principal_id,
                    correlation_id=correlation_id,
                    status="unknown",
                    duration_seconds=monotonic() - tool_started,
                    receipt=receipt,
                    verification=None,
                    error_code=action.failure_code,
                )
                raise UnknownOutcome(str(action_id)) from exc
            passed = bool(
                verification.get("passed")
                if isinstance(verification, dict)
                else getattr(verification, "passed", False)
            )
            if not passed:
                current = action.status
                if current == ActionStatus.APPROVED:
                    ensure_action_transition(
                        current, ActionStatus.COMMITTING, action_id=str(action_id)
                    )
                    action.status = ActionStatus.COMMITTING
                ensure_action_transition(
                    action.status, ActionStatus.VERIFY_FAILED, action_id=str(action_id)
                )
                action.status = ActionStatus.VERIFY_FAILED
                action.receipt = receipt
                action.verification = verification
                self._record_action(action, ActionStatus.VERIFY_FAILED)
                self._record_verification_failure(
                    "side_effect",
                    "SIDE_EFFECT_VERIFICATION_FAILED",
                )
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "commit",
                    "verify_failed",
                    monotonic() - tool_started,
                )
                self._stage_commit_audit(
                    transaction,
                    action,
                    decision=decision,
                    trajectory=trajectory,
                    principal_id=principal_id,
                    correlation_id=correlation_id,
                    status="verify_failed",
                    duration_seconds=monotonic() - tool_started,
                    receipt=receipt,
                    verification=verification,
                    error_code="SIDE_EFFECT_VERIFICATION_FAILED",
                )
                raise Conflict(
                    "SIDE_EFFECT_VERIFICATION_FAILED",
                    "External state did not match the receipt",
                    action_id=str(action_id),
                )
            if action.status == ActionStatus.APPROVED:
                ensure_action_transition(
                    action.status, ActionStatus.COMMITTING, action_id=str(action_id)
                )
                action.status = ActionStatus.COMMITTING
            ensure_action_transition(
                action.status, ActionStatus.COMMITTED, action_id=str(action_id)
            )
            action.status = ActionStatus.COMMITTED
            action.receipt = receipt
            action.verification = verification
            self._record_action(action, ActionStatus.COMMITTED)
            self._record_tool(
                action.tool_name,
                action.tool_version,
                "commit",
                "success",
                monotonic() - tool_started,
            )
            self._stage_commit_audit(
                transaction,
                action,
                decision=decision,
                trajectory=trajectory,
                principal_id=principal_id,
                correlation_id=correlation_id,
                status="succeeded",
                duration_seconds=monotonic() - tool_started,
                receipt=receipt,
                verification=verification,
            )
        return receipt

    async def compensate(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        principal_scopes: frozenset[str],
        action_id: UUID,
        correlation_id: str,
        reason: str,
    ) -> Any:

        event_run_id: UUID | None = None
        result: Any = None
        async with self._actions.get_for_update(action_id, tenant_id) as action:
            if action.status == ActionStatus.COMPENSATED:
                return action.verification
            if action.status not in {
                ActionStatus.COMMITTED,
                ActionStatus.VERIFY_FAILED,
            }:
                raise Conflict(
                    "INVALID_STATE_TRANSITION",
                    "Only a committed or verification-failed action may be compensated",
                    action_id=str(action_id),
                    status=action.status.value,
                )
            if action.receipt is None:
                raise Conflict(
                    "COMPENSATION_RECEIPT_MISSING",
                    "Compensation requires the original commit receipt",
                    action_id=str(action_id),
                )
            await self._require_commit_allowed(action, operation="compensate")
            policy_request = self._policy_request(
                action,
                tenant_id=tenant_id,
                principal_id=principal_id,
                principal_scopes=principal_scopes,
                phase="compensate",
            )
            policy_request["reason"] = reason
            decision = await self._policy.authorize_action(policy_request)
            self._record_policy("compensate", decision.allowed, decision.reason_codes)
            if not decision.allowed:
                raise Forbidden(
                    "ACTION_COMPENSATION_DENIED",
                    f"Compensation reauthorization denied: {','.join(decision.reason_codes)}",
                )
            tool = await self._registry.resolve_exact(
                action.tool_name, action.tool_version, tenant_id
            )
            credential = await self._credentials.issue(
                tenant_id,
                principal_id,
                principal_scopes
                & self._commit_scopes(tool.definition)
                & decision.credential_scopes,
                ttl_seconds=min(tool.definition.timeout_seconds + 5, 300),
            )
            ensure_action_transition(
                action.status,
                ActionStatus.COMPENSATING,
                action_id=str(action_id),
            )
            action.status = ActionStatus.COMPENSATING
            tool_started = monotonic()
            try:
                async with asyncio.timeout(tool.definition.timeout_seconds):
                    result = await tool.adapter.compensate(
                        action,
                        action.receipt,
                        credential,
                    )
            except Exception:
                ensure_action_transition(
                    action.status,
                    ActionStatus.COMPENSATION_FAILED,
                    action_id=str(action_id),
                )
                action.status = ActionStatus.COMPENSATION_FAILED
                action.failure_code = "COMPENSATION_FAILED"
                self._record_action(action, ActionStatus.COMPENSATION_FAILED)
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "compensate",
                    "error",
                    monotonic() - tool_started,
                )
                raise

            compensated = bool(
                result.get("compensated")
                if isinstance(result, dict)
                else getattr(result, "compensated", False)
            )
            if not compensated:
                ensure_action_transition(
                    action.status,
                    ActionStatus.COMPENSATION_FAILED,
                    action_id=str(action_id),
                )
                action.status = ActionStatus.COMPENSATION_FAILED
                action.failure_code = "COMPENSATION_FAILED"
                self._record_action(action, ActionStatus.COMPENSATION_FAILED)
                self._record_verification_failure(
                    "compensation",
                    "COMPENSATION_FAILED",
                )
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "compensate",
                    "verify_failed",
                    monotonic() - tool_started,
                )
                raise Conflict(
                    "COMPENSATION_FAILED",
                    "The external side effect could not be compensated",
                    action_id=str(action_id),
                )
            ensure_action_transition(
                action.status,
                ActionStatus.COMPENSATED,
                action_id=str(action_id),
            )
            action.status = ActionStatus.COMPENSATED
            action.verification = result
            action.failure_code = None
            self._record_action(action, ActionStatus.COMPENSATED)
            self._record_tool(
                action.tool_name,
                action.tool_version,
                "compensate",
                "success",
                monotonic() - tool_started,
            )
            event_run_id = action.run_id

        if event_run_id is not None:
            run = await self._runs.get(event_run_id, tenant_id)
            await self._runs.append_event(
                run,
                "action.compensated",
                {
                    "action_id": str(action_id),
                    "reason": reason,
                },
                correlation_id,
            )
        return result

    async def _trajectory_preflight_commit(
        self,
        action: ActionRecord,
        *,
        principal_id: str,
        principal_scopes: frozenset[str],
        correlation_id: str,
    ) -> TrajectoryCheck | None:
        guard = self._trajectory
        if guard is None:
            return None
        signals = inspect_trajectory_content(action.canonical_payload)
        check: TrajectoryCheck = await guard.preflight(
            run_id=action.run_id,
            tenant_id=action.tenant_id,
            candidate=TrajectoryCandidate(
                boundary="commit",
                task_id="commit",
                operation_name=action.tool_name,
                capability=action.action_type,
                args_hash=action.payload_hash,
                planned=True,
                injection_indicators=signals.injection_indicators,
                content_signal_hash=signals.content_signal_hash,
                credential_access_attempts=signals.credential_access_attempts,
                # The isolated commit worker is the actor, while the Action's
                # original principal remains the delegated security subject.
                principal_id=action.principal_id,
                principal_scopes=principal_scopes,
                action_id=action.action_id,
            ),
            correlation_id=correlation_id,
            actor_type="commit-worker",
            actor_id=principal_id,
        )
        return check

    @staticmethod
    def _policy_decision_id(action: ActionRecord, decision: Any) -> str:
        return payload_hash(
            {
                "action_id": str(action.action_id),
                "payload_hash": action.payload_hash,
                "policy_version": decision.policy_version,
                "allowed": decision.allowed,
                "reason_codes": list(decision.reason_codes),
                "credential_scopes": sorted(decision.credential_scopes),
            }
        )

    def _stage_commit_audit(
        self,
        transaction: ActionAuditTransaction,
        action: ActionRecord,
        *,
        decision: Any,
        trajectory: TrajectoryCheck | None,
        principal_id: str,
        correlation_id: str,
        status: str,
        duration_seconds: float,
        receipt: Any,
        verification: Any,
        error_code: str | None = None,
    ) -> None:
        completed_at = datetime.now(UTC)
        receipt_hash = payload_hash(receipt) if receipt is not None else None
        verification_hash = payload_hash(verification) if verification is not None else None
        decision_id = self._policy_decision_id(action, decision)
        invocation = ToolInvocationRecord(
            invocation_id=uuid4(),
            run_id=action.run_id,
            tenant_id=action.tenant_id,
            plan_version=0,
            task_id="commit",
            tool_name=action.tool_name,
            tool_version=action.tool_version,
            effect=ToolEffect.COMMIT,
            args_hash=action.payload_hash,
            args_redacted={key: "[REDACTED]" for key in sorted(action.canonical_payload)},
            data_scope_hash=payload_hash(
                {
                    "tenant_id": action.tenant_id,
                    "action_type": action.action_type,
                }
            ),
            policy_decision_id=decision_id,
            policy_version=decision.policy_version,
            status=status,
            result_hash=receipt_hash,
            error_code=error_code,
            latency_ms=max(int(duration_seconds * 1000), 0),
            provider_request_id=(
                str(receipt.get("provider_request_id"))
                if isinstance(receipt, dict) and receipt.get("provider_request_id")
                else None
            ),
            created_at=completed_at - timedelta(seconds=max(duration_seconds, 0.0)),
            completed_at=completed_at,
        )
        transaction.append_tool_invocation(invocation)
        event_type = {
            "succeeded": "action.committed",
            "verify_failed": "action.verify_failed",
            "unknown": "action.commit_unknown",
        }.get(status, "action.commit_recorded")
        transaction.append_event(
            AuditEvent(
                event_type=event_type,
                payload={
                    "action_id": str(action.action_id),
                    "tool_invocation_id": str(invocation.invocation_id),
                    "tool_name": action.tool_name,
                    "tool_version": action.tool_version,
                    "payload_hash": action.payload_hash,
                    "idempotency_key": action.idempotency_key,
                    "policy_decision_id": decision_id,
                    "policy_version": decision.policy_version,
                    "receipt_hash": receipt_hash,
                    "verification_hash": verification_hash,
                    "status": action.status.value,
                    "error_code": error_code,
                },
                correlation_id=correlation_id,
                actor_type="commit-worker",
                actor_id=principal_id,
                action_id=action.action_id,
            )
        )
        guard = self._trajectory
        if trajectory is not None and guard is not None:
            outcome_status = "succeeded" if status == "succeeded" else "failed"
            transaction.append_event(
                guard.outcome_event(
                    trajectory,
                    status=outcome_status,
                    error_code=(error_code if outcome_status == "failed" else None),
                )
            )

    def _record_policy(
        self,
        phase: str,
        allowed: bool,
        reason_codes: tuple[str, ...],
    ) -> None:
        if self._observability is not None:
            self._observability.record_policy(
                phase=phase,
                allowed=allowed,
                reason_codes=reason_codes,
            )

    def _record_action(self, action: ActionRecord, status: ActionStatus) -> None:
        if self._observability is not None:
            self._observability.record_action(
                action_type=action.action_type,
                risk=action.risk.value,
                status=status.value,
            )

    def _record_tool(
        self,
        tool_name: str,
        tool_version: str,
        effect: str,
        status: str,
        duration_seconds: float,
    ) -> None:
        if self._observability is not None:
            self._observability.record_tool(
                tool=tool_name,
                version=tool_version,
                effect=effect,
                status=status,
                duration_seconds=duration_seconds,
            )

    def _record_verification_failure(
        self,
        verifier: str,
        reason: str,
    ) -> None:
        if self._observability is not None:
            self._observability.record_verification_failure(
                verifier=verifier,
                reason=reason,
            )

    @staticmethod
    def _commit_scopes(definition: Any) -> frozenset[str]:
        configured: frozenset[str] = getattr(
            definition,
            "commit_scopes",
            frozenset(),
        )
        return configured or definition.required_scopes

    @staticmethod
    def _policy_request(
        action: Any,
        *,
        tenant_id: str,
        principal_id: str,
        principal_scopes: frozenset[str],
        phase: str,
    ) -> dict[str, Any]:
        approved = [
            record
            for record in action.approvals
            if isinstance(record, dict) and record.get("decision") == "approved"
        ]
        strength_order = {"password": 0, "mfa": 1, "phishing_resistant": 2}  # nosec B105
        approval_strength = min(
            (str(record.get("auth_strength", "password")) for record in approved),
            key=lambda item: strength_order.get(item, -1),
            default="password",
        )
        return {
            "principal": {
                "tenant_id": tenant_id,
                "user_id": principal_id,
                "scopes": sorted(principal_scopes),
                "auth_strength": approval_strength,
            },
            "action": {
                "action_id": str(action.action_id),
                "tenant_id": action.tenant_id,
                "principal_id": action.principal_id,
                "status": action.status.value,
                "payload_hash": action.payload_hash,
                "expires_at": action.expires_at.isoformat(),
                "risk": action.risk.value,
                "required_approvals": action.required_approvals,
                "expired": action.expires_at <= datetime.now(UTC),
                "kill_switch_active": False,
            },
            "approval": {"payload_hash": action.payload_hash},
            "approvals": approved,
            "tool": {
                "name": action.tool_name,
                "version": action.tool_version,
                "effect": "commit",
            },
            "caller": "commit-worker",
            "kill_switch": {"mode": "none"},
            "phase": phase,
        }

    async def _require_commit_allowed(
        self,
        action: Any,
        *,
        operation: str = "commit",
    ) -> None:
        if self._kill_switches is None:
            return
        run = await self._runs.get(action.run_id, action.tenant_id)
        configured = run.contract.constraints.get("use_case")
        use_case = (
            configured
            if isinstance(configured, str) and configured.strip()
            else run.contract.requested_output.schema_name
        )
        await self._kill_switches.require_allowed(
            tenant_id=action.tenant_id,
            use_case=use_case,
            capability=action.action_type,
            operation=operation,
        )

    async def reconcile_unknown(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        principal_scopes: frozenset[str],
        action_id: UUID,
        correlation_id: str,
    ) -> Any | None:
        """Resolve an UNKNOWN outcome without ever retrying the side effect.

        A missing idempotency-key lookup is affirmative evidence that the
        provider did not apply the operation. Only that evidence permits the
        guarded UNKNOWN -> APPROVED transition, and only while the exact
        approved payload is still valid.
        """

        event_run_id: UUID | None = None
        outcome: str | None = None
        result: Any | None = None
        expired = False
        async with self._actions.get_for_update(action_id, tenant_id) as action:
            if action.status != ActionStatus.UNKNOWN:
                raise Conflict(
                    "INVALID_STATE_TRANSITION",
                    "Only UNKNOWN actions may be reconciled",
                    action_id=str(action_id),
                )
            await self._require_commit_allowed(action, operation="reconcile")
            tool = await self._registry.resolve_exact(
                action.tool_name, action.tool_version, tenant_id
            )
            credential = await self._credentials.issue(
                tenant_id,
                principal_id,
                principal_scopes & self._commit_scopes(tool.definition),
                ttl_seconds=min(tool.definition.timeout_seconds + 5, 300),
            )
            tool_started = monotonic()
            try:
                receipt = await tool.adapter.lookup_by_idempotency_key(
                    action.idempotency_key, credential
                )
            except Exception:
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "reconcile",
                    "error",
                    monotonic() - tool_started,
                )
                raise

            if payload_hash(action.canonical_payload) != action.payload_hash:
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "reconcile",
                    "stale",
                    monotonic() - tool_started,
                )
                raise StaleActionHash(str(action_id))

            if receipt is None:
                if action.expires_at <= datetime.now(UTC):
                    ensure_action_transition(
                        action.status,
                        ActionStatus.EXPIRED,
                        action_id=str(action_id),
                    )
                    action.status = ActionStatus.EXPIRED
                    action.failure_code = "ACTION_EXPIRED"
                    outcome = "expired"
                    expired = True
                else:
                    ensure_action_transition(
                        action.status,
                        ActionStatus.APPROVED,
                        action_id=str(action_id),
                        reconciliation_confirmed_absent=True,
                    )
                    action.status = ActionStatus.APPROVED
                    action.failure_code = None
                    action.receipt = None
                    action.verification = None
                    outcome = "confirmed_absent"
                action.updated_at = datetime.now(UTC)
                event_run_id = action.run_id
                self._record_action(action, action.status)
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "reconcile",
                    outcome,
                    monotonic() - tool_started,
                )
            else:
                try:
                    verification = await tool.adapter.verify(
                        action,
                        receipt,
                        credential,
                    )
                except Exception:
                    self._record_tool(
                        action.tool_name,
                        action.tool_version,
                        "reconcile",
                        "error",
                        monotonic() - tool_started,
                    )
                    raise
                passed = bool(
                    verification.get("passed")
                    if isinstance(verification, dict)
                    else getattr(verification, "passed", False)
                )
                target = ActionStatus.COMMITTED if passed else ActionStatus.VERIFY_FAILED
                ensure_action_transition(
                    action.status,
                    target,
                    action_id=str(action_id),
                )
                action.status = target
                action.receipt = receipt
                action.verification = verification
                action.failure_code = None if passed else "SIDE_EFFECT_VERIFICATION_FAILED"
                action.updated_at = datetime.now(UTC)
                event_run_id = action.run_id
                outcome = "committed" if passed else "verify_failed"
                result = receipt if passed else None
                self._record_action(action, target)
                if not passed:
                    self._record_verification_failure(
                        "side_effect_reconciliation",
                        "SIDE_EFFECT_VERIFICATION_FAILED",
                    )
                self._record_tool(
                    action.tool_name,
                    action.tool_version,
                    "reconcile",
                    "success" if passed else "verify_failed",
                    monotonic() - tool_started,
                )

        if event_run_id is not None and outcome is not None:
            run = await self._runs.get(event_run_id, tenant_id)
            await self._runs.append_event(
                run,
                "action.reconciled",
                {
                    "action_id": str(action_id),
                    "outcome": outcome,
                    "payload_hash": action.payload_hash,
                    "idempotency_key": action.idempotency_key,
                },
                correlation_id,
            )
        if expired:
            raise Conflict(
                "ACTION_EXPIRED",
                "Action approval expired after reconciliation confirmed absence",
                action_id=str(action_id),
            )
        return result
