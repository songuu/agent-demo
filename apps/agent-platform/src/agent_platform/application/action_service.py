from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from agent_platform.application.errors import (
    Conflict,
    Forbidden,
    StaleActionHash,
    WorkflowSignalFailed,
)
from agent_platform.application.records import AuditEvent
from agent_platform.domain.enums import ActionStatus, ApprovalDecision, RiskLevel
from agent_platform.domain.state_machines import ensure_action_transition
from agent_platform.infrastructure.observability.runtime import RuntimeObservability


class ActionService:
    def __init__(
        self,
        actions: Any,
        workflow: Any,
        *,
        observability: RuntimeObservability | None = None,
    ) -> None:
        self._actions = actions
        self._workflow = workflow
        self._observability = observability

    async def decide(
        self,
        action_id: UUID,
        *,
        tenant_id: str,
        actor_id: str,
        actor_roles: frozenset[str],
        auth_strength: str,
        decision: str,
        expected_payload_hash: str,
        comment: str | None,
    ) -> Any:
        normalized = ApprovalDecision(decision)
        notify: str | None = None
        persisted = await self._actions.get(action_id, tenant_id)
        if persisted.payload_hash != expected_payload_hash:
            raise StaleActionHash(str(action_id))
        retry_target = (
            ActionStatus.APPROVED
            if normalized == ApprovalDecision.APPROVED
            else ActionStatus.REJECTED
        )
        matching_decision = any(
            record.get("actor_id") == actor_id
            and record.get("decision") == normalized.value
            and record.get("payload_hash") == expected_payload_hash
            for record in persisted.approvals
        )
        if persisted.status == retry_target and matching_decision:
            await self._notify_workflow(action_id, tenant_id, normalized.value)
            return persisted
        async with self._actions.transaction(action_id, tenant_id) as transaction:
            action = transaction.action
            if action.payload_hash != expected_payload_hash:
                raise StaleActionHash(str(action_id))
            if action.status != ActionStatus.PENDING_APPROVAL:
                raise Conflict(
                    "INVALID_STATE_TRANSITION",
                    "Action is not waiting for approval",
                    action_id=str(action_id),
                    current=action.status.value,
                )
            if action.expires_at <= datetime.now(UTC):
                ensure_action_transition(
                    action.status, ActionStatus.EXPIRED, action_id=str(action_id)
                )
                action.status = ActionStatus.EXPIRED
                transaction.append_event(
                    AuditEvent(
                        event_type="action.expired",
                        payload={
                            "action_id": str(action_id),
                            "payload_hash": action.payload_hash,
                            "policy_version": action.policy_version,
                            "status": action.status.value,
                        },
                        correlation_id=f"action-expired:{action_id}",
                        actor_type="application",
                        action_id=action_id,
                    )
                )
                raise Conflict(
                    "ACTION_EXPIRED", "Prepared action has expired", action_id=str(action_id)
                )
            if actor_id == action.principal_id:
                raise Forbidden(
                    "SEPARATION_OF_DUTIES_REQUIRED",
                    "Approval requires separation between requester and approver",
                )
            required_auth_strength = (
                "phishing_resistant" if action.risk == RiskLevel.CRITICAL else "mfa"
            )
            allowed_auth_strengths = (
                {"phishing_resistant"}
                if required_auth_strength == "phishing_resistant"
                else {"mfa", "phishing_resistant"}
            )
            if auth_strength not in allowed_auth_strengths:
                raise Forbidden(
                    "STEP_UP_AUTH_REQUIRED",
                    f"Approval requires {required_auth_strength} step-up authentication",
                )
            if "approver" not in actor_roles and "admin" not in actor_roles:
                raise Forbidden("APPROVER_ROLE_REQUIRED", "Actor lacks the approval role")
            if any(record["actor_id"] == actor_id for record in action.approvals):
                raise Conflict(
                    "DUPLICATE_APPROVAL",
                    "The same actor cannot approve the payload twice",
                    actor_id=actor_id,
                )

            approval_id = uuid4()
            action.approvals.append(
                {
                    "approval_id": str(approval_id),
                    "actor_id": actor_id,
                    "actor_roles": sorted(actor_roles),
                    "auth_strength": auth_strength,
                    "decision": normalized.value,
                    "comment": comment,
                    "policy_version": action.policy_version,
                    "payload_hash": expected_payload_hash,
                    "created_at": datetime.now(UTC).isoformat(),
                }
            )
            if normalized == ApprovalDecision.REJECTED:
                ensure_action_transition(
                    action.status, ActionStatus.REJECTED, action_id=str(action_id)
                )
                action.status = ActionStatus.REJECTED
                notify = "rejected"
            else:
                distinct_approvers = {
                    record["actor_id"]
                    for record in action.approvals
                    if record["decision"] == ApprovalDecision.APPROVED.value
                }
                if len(distinct_approvers) >= action.required_approvals:
                    ensure_action_transition(
                        action.status, ActionStatus.APPROVED, action_id=str(action_id)
                    )
                    action.status = ActionStatus.APPROVED
                    notify = "approved"
            transaction.append_event(
                AuditEvent(
                    event_type="action.approval_recorded",
                    payload={
                        "action_id": str(action_id),
                        "approval_id": str(approval_id),
                        "decision": normalized.value,
                        "actor_id": actor_id,
                        "actor_roles": sorted(actor_roles),
                        "auth_strength": auth_strength,
                        "payload_hash": expected_payload_hash,
                        "policy_version": action.policy_version,
                        "required_approvals": action.required_approvals,
                        "recorded_approvals": len(action.approvals),
                        "status": action.status.value,
                    },
                    correlation_id=f"approval:{approval_id}",
                    actor_type="user",
                    actor_id=actor_id,
                    action_id=action_id,
                )
            )
            result = action
            approval_duration = max(
                (datetime.now(UTC) - action.created_at).total_seconds(),
                0.0,
            )
            observed_action_type = action.action_type
            observed_policy = action.approval_policy
            observed_risk = action.risk.value
            observed_status = action.status.value
        if self._observability is not None:
            with self._observability.span(
                "agent.approval.decision",
                {
                    "action_type": observed_action_type,
                    "policy": observed_policy,
                    "decision": normalized.value,
                    "risk": observed_risk,
                    "status": observed_status,
                },
            ):
                self._observability.record_approval(
                    policy=observed_policy,
                    decision=normalized.value,
                    duration_seconds=approval_duration,
                )
                if notify is not None:
                    self._observability.record_action(
                        action_type=observed_action_type,
                        risk=observed_risk,
                        status=observed_status,
                    )
        if notify is not None:
            await self._notify_workflow(action_id, tenant_id, notify)
        return result

    async def _notify_workflow(
        self,
        action_id: UUID,
        tenant_id: str,
        decision: str,
    ) -> None:
        try:
            await self._workflow.notify_action(action_id, tenant_id, decision)
        except Exception as exc:
            raise WorkflowSignalFailed(
                "action",
                str(action_id),
                f"decision:{decision}",
            ) from exc
