"""OPA HTTP adapter with explicit fail-closed behavior."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

_POLICY_PATH = re.compile(r"^[a-zA-Z0-9_./-]+$")


class PolicyEvaluationError(RuntimeError):
    """Raised when policy infrastructure fails and fail-closed is disabled."""


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    reason_codes: tuple[str, ...] = ()
    approval_required: bool = False
    data_scope: dict[str, Any] = field(default_factory=dict)
    policy_version: str = "unknown"
    decision_id: str | None = None


class OpaPolicyEngine:
    """Evaluate versioned OPA data documents.

    OPA errors are authorization failures by default. This adapter never falls
    back to allow-all and preserves stable reason codes for audit events.
    """

    def __init__(
        self,
        *,
        base_url: str,
        client: httpx.AsyncClient | None = None,
        fail_closed: bool = True,
        timeout_seconds: float = 2.0,
    ) -> None:
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
        )
        self._fail_closed = fail_closed

    async def __aenter__(self) -> OpaPolicyEngine:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owned_client:
            await self._client.aclose()

    async def evaluate(
        self,
        policy_path: str,
        policy_input: dict[str, Any],
    ) -> PolicyDecision:
        normalized = policy_path.strip("/")
        if not normalized or not _POLICY_PATH.fullmatch(normalized) or ".." in normalized:
            raise ValueError("policy_path contains unsupported characters")

        try:
            response = await self._client.post(
                f"/v1/data/{normalized}",
                json={"input": policy_input},
            )
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            return self._failure("policy_unavailable", exc)

        raw = body.get("result") if isinstance(body, dict) else None
        if not isinstance(raw, dict):
            return self._failure(
                "invalid_policy_response",
                PolicyEvaluationError("OPA response has no object result"),
            )

        allowed = raw.get("allowed")
        if not isinstance(allowed, bool):
            allowed = raw.get("allow_commit", raw.get("allow_egress"))
        if not isinstance(allowed, bool):
            return self._failure(
                "invalid_policy_response",
                PolicyEvaluationError("OPA result has no boolean decision"),
            )

        reasons = raw.get("reason_codes", ())
        if isinstance(reasons, dict):
            reasons = tuple(sorted(str(item) for item in reasons))
        elif isinstance(reasons, list):
            reasons = tuple(str(item) for item in reasons)
        elif not isinstance(reasons, tuple):
            reasons = ()
        data_scope = raw.get("data_scope", {})
        if not isinstance(data_scope, dict):
            data_scope = {}

        return PolicyDecision(
            allowed=allowed,
            reason_codes=tuple(reasons),
            approval_required=bool(raw.get("approval_required", False)),
            data_scope=data_scope,
            policy_version=str(raw.get("policy_version", "unknown")),
            decision_id=(str(raw["decision_id"]) if raw.get("decision_id") is not None else None),
        )

    def _failure(self, code: str, cause: Exception) -> PolicyDecision:
        if not self._fail_closed:
            raise PolicyEvaluationError(f"{code}: {cause}") from cause
        return PolicyDecision(
            allowed=False,
            reason_codes=(code,),
            policy_version="unavailable",
        )
