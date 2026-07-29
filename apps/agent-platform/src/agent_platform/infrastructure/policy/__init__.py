"""Fail-closed policy service adapters."""

from agent_platform.infrastructure.policy.engine import (
    OpaPolicyEngine,
    PolicyDecision,
    PolicyEvaluationError,
)

__all__ = ["OpaPolicyEngine", "PolicyDecision", "PolicyEvaluationError"]
