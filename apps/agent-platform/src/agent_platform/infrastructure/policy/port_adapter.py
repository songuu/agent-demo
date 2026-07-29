"""Application PolicyEngine port backed by the fail-closed OPA HTTP client."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_platform.infrastructure.policy.engine import OpaPolicyEngine
from agent_platform.tools.models import PolicyDecision


class OpaPolicyPortAdapter:
    """Map OPA documents to the richer decision used by tool/commit services."""

    def __init__(
        self,
        engine: OpaPolicyEngine,
        *,
        tool_policy_path: str = "agent/tool/result",
        action_policy_path: str = "agent/action/result",
        tool_decision_ttl_seconds: int = 900,
        action_decision_ttl_seconds: int = 300,
    ) -> None:
        if tool_decision_ttl_seconds < 1 or action_decision_ttl_seconds < 1:
            raise ValueError("POLICY_DECISION_TTL_MUST_BE_POSITIVE")
        self._engine = engine
        self._tool_policy_path = tool_policy_path
        self._action_policy_path = action_policy_path
        self._tool_ttl = tool_decision_ttl_seconds
        self._action_ttl = action_decision_ttl_seconds

    async def authorize_tool(self, request: Mapping[str, Any]) -> PolicyDecision:
        policy_request = dict(request)
        decision = await self._engine.evaluate(
            self._tool_policy_path,
            policy_request,
        )
        principal = self._mapping(policy_request.get("principal"))
        tool = self._mapping(policy_request.get("tool"))
        request_context = self._mapping(policy_request.get("request"))
        principal_scopes = frozenset(str(value) for value in principal.get("scopes", ()))
        required_scopes = frozenset(str(value) for value in tool.get("required_scopes", ()))
        credential_scopes = (
            principal_scopes & required_scopes if required_scopes else principal_scopes
        )
        risk = str(tool.get("risk", "low"))
        required_approvals = (
            2
            if decision.approval_required and risk == "critical"
            else 1
            if decision.approval_required
            else 0
        )
        restricted_scope = decision.data_scope or dict(
            self._mapping(request_context.get("data_scope"))
        )
        return PolicyDecision(
            allowed=decision.allowed,
            reason_codes=decision.reason_codes,
            approval_required=decision.approval_required,
            policy_version=decision.policy_version,
            credential_scopes=credential_scopes,
            expires_at=datetime.now(UTC) + timedelta(seconds=self._tool_ttl),
            required_approvals=required_approvals,
            restricted_data_scope=restricted_scope,
        )

    async def authorize_action(self, request: Mapping[str, Any]) -> PolicyDecision:
        policy_request = dict(request)
        decision = await self._engine.evaluate(
            self._action_policy_path,
            policy_request,
        )
        principal = self._mapping(policy_request.get("principal"))
        return PolicyDecision(
            allowed=decision.allowed,
            reason_codes=decision.reason_codes,
            approval_required=False,
            policy_version=decision.policy_version,
            credential_scopes=frozenset(str(value) for value in principal.get("scopes", ())),
            expires_at=datetime.now(UTC) + timedelta(seconds=self._action_ttl),
            required_approvals=0,
            restricted_data_scope=None,
        )

    async def aclose(self) -> None:
        await self._engine.aclose()

    @staticmethod
    def _mapping(value: Any) -> Mapping[str, Any]:
        return value if isinstance(value, Mapping) else {}
