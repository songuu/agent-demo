from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.kill_switch import (
    KillSwitchRegistry,
    KillSwitchScope,
)


@pytest.mark.asyncio
async def test_global_switch_preserves_queries_but_blocks_new_execution() -> None:
    registry = KillSwitchRegistry(environment="prod")
    await registry.activate(
        scope=KillSwitchScope.GLOBAL,
        scope_id="*",
        mode="all",
        reason="SEC-010 exercise",
        changed_by="security-1",
        incident_id="INC-42",
    )

    await registry.require_allowed(
        tenant_id="tenant-a",
        use_case="research",
        capability="knowledge.search",
        operation="query",
    )
    for operation in ("run_create", "model", "tool", "commit"):
        with pytest.raises(PlatformError, match="GLOBAL_KILL_SWITCH_ACTIVE"):
            await registry.require_allowed(
                tenant_id="tenant-a",
                use_case="research",
                capability="knowledge.search",
                operation=operation,
            )


@pytest.mark.asyncio
async def test_tenant_and_capability_switches_do_not_affect_other_tenants() -> None:
    registry = KillSwitchRegistry(environment="prod")
    await registry.activate(
        scope=KillSwitchScope.TENANT,
        scope_id="tenant-a",
        mode="all",
        reason="Tenant isolation",
        changed_by="security-1",
        incident_id="INC-43",
    )
    await registry.activate(
        scope=KillSwitchScope.CAPABILITY,
        scope_id="email.prepare",
        mode="writes",
        reason="Provider incident",
        changed_by="sre-1",
        incident_id="INC-44",
    )

    with pytest.raises(PlatformError, match="TENANT_KILL_SWITCH_ACTIVE"):
        await registry.require_allowed(
            tenant_id="tenant-a",
            use_case="assistant",
            capability="knowledge.search",
            operation="tool",
        )
    await registry.require_allowed(
        tenant_id="tenant-b",
        use_case="assistant",
        capability="knowledge.search",
        operation="tool",
    )
    with pytest.raises(PlatformError, match="CAPABILITY_KILL_SWITCH_ACTIVE"):
        await registry.require_allowed(
            tenant_id="tenant-b",
            use_case="assistant",
            capability="email.prepare",
            operation="commit",
        )
    await registry.require_allowed(
        tenant_id="tenant-b",
        use_case="assistant",
        capability="email.prepare",
        operation="query",
    )


@pytest.mark.asyncio
async def test_expired_switch_is_ignored_and_changes_are_audited() -> None:
    registry = KillSwitchRegistry(environment="prod")
    now = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)
    record = await registry.activate(
        scope=KillSwitchScope.USE_CASE,
        scope_id="research",
        mode="all",
        reason="Drill",
        changed_by="sre-1",
        incident_id="CHG-1",
        expires_at=now + timedelta(minutes=5),
        now=now,
    )

    await registry.require_allowed(
        tenant_id="tenant-a",
        use_case="research",
        capability="knowledge.search",
        operation="run_create",
        now=now + timedelta(minutes=6),
    )
    await registry.deactivate(
        record.switch_id,
        changed_by="sre-2",
        reason="Drill complete",
        now=now + timedelta(minutes=7),
    )
    audit = await registry.audit_log()
    assert [(item.action, item.changed_by) for item in audit] == [
        ("activated", "sre-1"),
        ("deactivated", "sre-2"),
    ]
