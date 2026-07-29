"""Fail-closed deterministic policy used in tests and local development.

Production selects the OPA adapter. This policy still enforces the immutable
boundaries in code, so an accidental backend switch cannot create allow-all.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from agent_platform.tools.models import PolicyDecision


class BuiltinPolicyEngine:
    policy_version = "builtin-1"

    async def authorize_tool(self, request: dict[str, Any]) -> PolicyDecision:
        principal = request.get("principal", {})
        task = request.get("task", {})
        tool = request.get("tool", {})
        data_scope = request.get("request", {}).get("data_scope", {})
        reasons: list[str] = []

        tenant_id = principal.get("tenant_id")
        if not tenant_id or data_scope.get("tenant_id") != tenant_id:
            reasons.append("cross_tenant_scope")
        if tool.get("name") not in task.get("allowed_capabilities", []):
            reasons.append("capability_not_allowed")
        if tool.get("effect") == "commit":
            reasons.append("commit_not_agent_visible")
        if tool.get("risk") == "critical":
            reasons.append("critical_default_deny")

        effect = tool.get("effect")
        risk = tool.get("risk")
        approval_required = effect == "prepare" and risk in {"medium", "high", "critical"}
        required_approvals = 2 if risk == "critical" else (1 if approval_required else 0)
        scopes = frozenset(str(value) for value in principal.get("scopes", ()))
        return PolicyDecision(
            allowed=not reasons,
            reason_codes=tuple(reasons),
            approval_required=approval_required,
            policy_version=self.policy_version,
            credential_scopes=scopes,
            required_approvals=required_approvals,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            restricted_data_scope=dict(data_scope),
        )

    async def authorize_action(self, request: dict[str, Any]) -> PolicyDecision:
        principal = request.get("principal", {})
        action = request.get("action", {})
        reasons: list[str] = []
        if principal.get("tenant_id") != action.get("tenant_id"):
            reasons.append("cross_tenant_scope")
        if action.get("status") != "approved":
            reasons.append("action_not_approved")
        if action.get("expired"):
            reasons.append("action_expired")
        if action.get("kill_switch_active"):
            reasons.append("kill_switch_active")
        return PolicyDecision(
            allowed=not reasons,
            reason_codes=tuple(reasons),
            approval_required=False,
            policy_version=self.policy_version,
            credential_scopes=frozenset(str(value) for value in principal.get("scopes", ())),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            required_approvals=0,
        )
