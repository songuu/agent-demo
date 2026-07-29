from __future__ import annotations

from pathlib import Path

POLICY_DIR = Path(__file__).parents[3] / "policies"


def test_tool_policy_denies_agent_commit_and_cross_tenant_access() -> None:
    source = (POLICY_DIR / "tool.rego").read_text(encoding="utf-8")

    assert "default allow := false" in source
    assert '"tenant_mismatch"' in source
    assert '"effect_not_allowed"' in source
    assert 'input.tool.effect == "commit"' in source
    assert "kill_switch" in source


def test_action_policy_checks_hash_expiry_approval_count_and_separation() -> None:
    source = (POLICY_DIR / "action.rego").read_text(encoding="utf-8")

    for invariant in (
        "payload_unchanged",
        "not_expired",
        "required_count_ok",
        "separation_ok",
        "commit-worker",
        "kill_switch",
    ):
        assert invariant in source


def test_sandbox_policy_is_default_deny() -> None:
    source = (POLICY_DIR / "sandbox.rego").read_text(encoding="utf-8")

    assert "default allow_egress := false" in source
    assert "is_private_ip" in source
    assert "is_metadata_service" in source
