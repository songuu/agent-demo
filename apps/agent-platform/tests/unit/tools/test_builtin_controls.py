from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent_platform.infrastructure.credentials import EphemeralCredentialBroker
from agent_platform.tools.function_tools import prepare_email
from agent_platform.tools.policy import BuiltinPolicyEngine


def test_prepare_tool_uses_prepared_action_approval_not_sdk_interruption() -> None:
    assert prepare_email.needs_approval is False


@pytest.mark.asyncio
async def test_builtin_policy_fails_closed_on_cross_tenant_and_commit_exposure() -> None:
    policy = BuiltinPolicyEngine()
    base = {
        "principal": {
            "tenant_id": "tenant-a",
            "user_id": "user-1",
            "scopes": ["knowledge:read"],
        },
        "task": {"allowed_capabilities": ["knowledge.search"]},
        "tool": {
            "name": "knowledge.search",
            "effect": "read",
            "risk": "medium",
        },
        "request": {"data_scope": {"tenant_id": "tenant-b"}},
    }

    cross_tenant = await policy.authorize_tool(base)
    assert cross_tenant.allowed is False
    assert "cross_tenant_scope" in cross_tenant.reason_codes

    base["request"]["data_scope"]["tenant_id"] = "tenant-a"
    base["tool"]["effect"] = "commit"
    commit = await policy.authorize_tool(base)
    assert commit.allowed is False
    assert "commit_not_agent_visible" in commit.reason_codes


@pytest.mark.asyncio
async def test_critical_actions_are_default_denied_and_high_actions_require_approval() -> None:
    policy = BuiltinPolicyEngine()
    request = {
        "principal": {
            "tenant_id": "tenant-a",
            "user_id": "user-1",
            "scopes": ["email:prepare"],
        },
        "task": {"allowed_capabilities": ["email.prepare"]},
        "tool": {"name": "email.prepare", "effect": "prepare", "risk": "critical"},
        "request": {"data_scope": {"tenant_id": "tenant-a"}},
    }
    critical = await policy.authorize_tool(request)
    assert critical.allowed is False

    request["tool"]["risk"] = "high"
    high = await policy.authorize_tool(request)
    assert high.allowed is True
    assert high.approval_required is True


@pytest.mark.asyncio
async def test_ephemeral_credentials_have_scope_and_expiry_but_no_secret_material() -> None:
    broker = EphemeralCredentialBroker()
    credential = await broker.issue(
        "tenant-a", "user-1", frozenset({"knowledge:read"}), ttl_seconds=30
    )

    assert credential.tenant_id == "tenant-a"
    assert credential.scopes == frozenset({"knowledge:read"})
    assert credential.expires_at > datetime.now(UTC)
    assert "token" not in repr(credential).lower()
