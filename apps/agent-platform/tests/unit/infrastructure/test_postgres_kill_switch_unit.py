from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy.dialects import postgresql

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.kill_switch import KillSwitchScope
from agent_platform.infrastructure.persistence.governance_models import (
    KillSwitchAuditRow,
    ScopedKillSwitch,
)
from agent_platform.infrastructure.persistence.postgres_kill_switch import (
    PostgresKillSwitchRegistry,
)

NOW = datetime(2026, 7, 24, 9, 0, tzinfo=UTC)


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        scalar_row_sets: list[list[Any]] | None = None,
        execute_error: Exception | None = None,
    ) -> None:
        self._scalar_results = deque(scalar_results or [])
        self._scalar_row_sets = deque(scalar_row_sets or [])
        self._execute_error = execute_error
        self.added: list[Any] = []
        self.statements: list[Any] = []
        self.begins = 0
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0
        self._in_transaction = False

    async def begin(self) -> None:
        self.begins += 1
        self._in_transaction = True

    async def execute(self, statement: Any) -> None:
        self.statements.append(statement)
        if self._execute_error is not None:
            raise self._execute_error

    async def scalar(self, statement: Any) -> Any:
        self.statements.append(statement)
        return self._scalar_results.popleft()

    async def scalars(self, statement: Any) -> _Rows:
        self.statements.append(statement)
        return _Rows(self._scalar_row_sets.popleft())

    def add(self, value: Any) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1
        self._in_transaction = False

    def in_transaction(self) -> bool:
        return self._in_transaction

    async def rollback(self) -> None:
        self.rollbacks += 1
        self._in_transaction = False

    async def close(self) -> None:
        self.closes += 1


class _Factory:
    def __init__(self, *sessions: _Session) -> None:
        self._sessions = deque(sessions)
        self.calls = 0

    def __call__(self) -> _Session:
        self.calls += 1
        return self._sessions.popleft()


def _row(
    *,
    switch_id: UUID | None = None,
    scope: KillSwitchScope = KillSwitchScope.TENANT,
    scope_id: str = "tenant-a",
    mode: str = "writes",
    deactivated_at: datetime | None = None,
) -> ScopedKillSwitch:
    return ScopedKillSwitch(
        switch_id=switch_id or uuid4(),
        tenant_partition=scope_id if scope is KillSwitchScope.TENANT else "*",
        scope=scope.value,
        scope_id=scope_id,
        mode=mode,
        reason="Incident response",
        changed_by="secops",
        incident_id="INC-1",
        activated_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        deactivated_at=deactivated_at,
        deactivated_by=None,
        deactivation_reason=None,
    )


def _audit_row(switch_id: UUID) -> KillSwitchAuditRow:
    return KillSwitchAuditRow(
        audit_id=uuid4(),
        switch_id=switch_id,
        tenant_partition="tenant-a",
        action="activated",
        scope=KillSwitchScope.TENANT.value,
        scope_id="tenant-a",
        mode="writes",
        changed_by="secops",
        reason="Incident response",
        incident_id="INC-1",
        created_at=NOW,
    )


def _registry(
    *,
    tenant_factory: _Factory | None = None,
    management_factory: _Factory | None = None,
) -> PostgresKillSwitchRegistry:
    return PostgresKillSwitchRegistry(
        cast(Any, tenant_factory or _Factory()),
        environment="prod",
        management_factory=(
            cast(Any, management_factory) if management_factory is not None else None
        ),
    )


def _patch_tenant_sessions(
    monkeypatch: pytest.MonkeyPatch,
    sessions: list[_Session],
    captured_tenants: list[str],
) -> None:
    queue = deque(sessions)

    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        captured_tenants.append(tenant_id)
        yield queue.popleft()

    monkeypatch.setattr(
        "agent_platform.infrastructure.persistence.postgres_kill_switch.tenant_session",
        fake_tenant_session,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"mode": "reads"}, "KILL_SWITCH_MODE_INVALID"),
        ({"scope_id": " "}, "KILL_SWITCH_AUDIT_FIELDS_REQUIRED"),
        ({"reason": " "}, "KILL_SWITCH_AUDIT_FIELDS_REQUIRED"),
        ({"expires_at": NOW}, "KILL_SWITCH_EXPIRY_INVALID"),
        (
            {"scope": KillSwitchScope.ENVIRONMENT, "scope_id": "staging"},
            "KILL_SWITCH_ENVIRONMENT_MISMATCH",
        ),
    ],
)
async def test_activate_rejects_invalid_or_unauditable_switches(
    overrides: dict[str, Any],
    message: str,
) -> None:
    values: dict[str, Any] = {
        "scope": KillSwitchScope.TENANT,
        "scope_id": "tenant-a",
        "mode": "writes",
        "reason": "Incident response",
        "changed_by": "secops",
        "incident_id": "INC-1",
        "expires_at": NOW + timedelta(hours=1),
        "now": NOW,
    }

    with pytest.raises(ValueError, match=message):
        await _registry().activate(**{**values, **overrides})


async def test_tenant_activation_uses_rls_partition_and_persists_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session()
    tenants: list[str] = []
    _patch_tenant_sessions(monkeypatch, [session], tenants)
    registry = _registry()

    record = await registry.activate(
        scope=KillSwitchScope.TENANT,
        scope_id="tenant-a",
        mode="writes",
        reason="Incident response",
        changed_by="secops",
        incident_id="INC-1",
        expires_at=NOW + timedelta(hours=1),
        now=NOW,
    )

    database_record, audit = session.added
    assert tenants == ["tenant-a"]
    assert session.flushes == 1
    assert session.commits == 1
    assert database_record.switch_id == record.switch_id
    assert database_record.tenant_partition == "tenant-a"
    assert database_record.scope == "tenant"
    assert database_record.expires_at == NOW + timedelta(hours=1)
    assert audit.switch_id == record.switch_id
    assert audit.tenant_partition == "tenant-a"
    assert audit.action == "activated"
    assert audit.created_at == NOW


async def test_global_activation_uses_management_role_and_commits() -> None:
    session = _Session()
    management = _Factory(session)
    registry = _registry(management_factory=management)

    record = await registry.activate(
        scope=KillSwitchScope.GLOBAL,
        scope_id="*",
        mode="all",
        reason="Global incident",
        changed_by="secops",
        incident_id="INC-2",
        now=NOW,
    )

    database_record, audit = session.added
    assert record.scope is KillSwitchScope.GLOBAL
    assert database_record.tenant_partition == "*"
    assert audit.tenant_partition == "*"
    assert session.begins == 1
    assert session.commits == 1
    assert session.rollbacks == 0
    assert session.closes == 1
    assert "set_config('app.tenant_id', '*', true)" in str(session.statements[0])


async def test_management_operations_fail_closed_without_dedicated_role() -> None:
    registry = _registry()

    with pytest.raises(PlatformError) as raised:
        await registry.activate(
            scope=KillSwitchScope.GLOBAL,
            scope_id="*",
            mode="all",
            reason="Global incident",
            changed_by="secops",
            incident_id="INC-2",
            now=NOW,
        )

    assert raised.value.code == "KILL_SWITCH_MANAGEMENT_ROLE_REQUIRED"
    assert raised.value.http_status == 503


async def test_management_session_rolls_back_and_closes_when_setup_fails() -> None:
    session = _Session(execute_error=RuntimeError("database unavailable"))
    registry = _registry(management_factory=_Factory(session))

    with pytest.raises(RuntimeError, match="database unavailable"):
        await registry.active(now=NOW)

    assert session.begins == 1
    assert session.rollbacks == 1
    assert session.closes == 1


@pytest.mark.parametrize(("changed_by", "reason"), [("", "recovered"), ("secops", " ")])
async def test_deactivate_requires_audit_fields(changed_by: str, reason: str) -> None:
    with pytest.raises(ValueError, match="KILL_SWITCH_AUDIT_FIELDS_REQUIRED"):
        await _registry().deactivate(
            uuid4(),
            changed_by=changed_by,
            reason=reason,
            now=NOW,
        )


async def test_deactivate_missing_switch_rolls_back_management_transaction() -> None:
    session = _Session(scalar_results=[None])
    registry = _registry(management_factory=_Factory(session))
    switch_id = uuid4()

    with pytest.raises(PlatformError) as raised:
        await registry.deactivate(
            switch_id,
            changed_by="secops",
            reason="Recovered",
            now=NOW,
        )

    assert raised.value.code == "NOT_FOUND"
    assert raised.value.http_status == 404
    assert session.rollbacks == 1
    assert session.closes == 1
    rendered = str(
        session.statements[1].compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert f"kill_switches.switch_id = '{switch_id}'" in rendered
    assert "FOR UPDATE" in rendered


async def test_deactivate_is_idempotent_and_audits_only_first_transition() -> None:
    row = _row()
    first = _Session(scalar_results=[row])
    second = _Session(scalar_results=[row])
    registry = _registry(management_factory=_Factory(first, second))

    deactivated = await registry.deactivate(
        row.switch_id,
        changed_by="secops",
        reason="Recovered",
        now=NOW + timedelta(minutes=10),
    )
    repeated = await registry.deactivate(
        row.switch_id,
        changed_by="different-actor",
        reason="Repeated request",
        now=NOW + timedelta(minutes=20),
    )

    assert deactivated.deactivated_at == NOW + timedelta(minutes=10)
    assert deactivated.deactivated_by == "secops"
    assert deactivated.deactivation_reason == "Recovered"
    assert repeated.deactivated_at == deactivated.deactivated_at
    assert len(first.added) == 1
    assert first.added[0].action == "deactivated"
    assert first.added[0].tenant_partition == "tenant-a"
    assert second.added == []
    assert first.commits == second.commits == 1
    assert first.closes == second.closes == 1


async def test_query_operation_short_circuits_without_database_access() -> None:
    tenant_factory = _Factory()
    registry = _registry(tenant_factory=tenant_factory)

    await registry.require_allowed(
        tenant_id="tenant-a",
        use_case="report",
        capability="email.prepare",
        operation="query",
        now=NOW,
    )

    assert tenant_factory.calls == 0


@pytest.mark.parametrize(
    ("scope", "scope_id", "mode", "operation", "code"),
    [
        (KillSwitchScope.GLOBAL, "*", "all", "execute", "GLOBAL_KILL_SWITCH_ACTIVE"),
        (
            KillSwitchScope.ENVIRONMENT,
            "prod",
            "writes",
            "prepare",
            "ENVIRONMENT_KILL_SWITCH_ACTIVE",
        ),
        (
            KillSwitchScope.TENANT,
            "tenant-a",
            "writes",
            "commit",
            "TENANT_KILL_SWITCH_ACTIVE",
        ),
        (
            KillSwitchScope.USE_CASE,
            "report",
            "writes",
            "write",
            "USE_CASE_KILL_SWITCH_ACTIVE",
        ),
        (
            KillSwitchScope.CAPABILITY,
            "email.prepare",
            "all",
            "execute",
            "CAPABILITY_KILL_SWITCH_ACTIVE",
        ),
    ],
)
async def test_require_allowed_blocks_every_hierarchical_scope(
    monkeypatch: pytest.MonkeyPatch,
    scope: KillSwitchScope,
    scope_id: str,
    mode: str,
    operation: str,
    code: str,
) -> None:
    session = _Session(scalar_row_sets=[[_row(scope=scope, scope_id=scope_id, mode=mode)]])
    tenants: list[str] = []
    _patch_tenant_sessions(monkeypatch, [session], tenants)

    with pytest.raises(PlatformError) as raised:
        await _registry().require_allowed(
            tenant_id="tenant-a",
            use_case="report",
            capability="email.prepare",
            operation=operation,
            now=NOW,
        )

    assert raised.value.code == code
    assert raised.value.http_status == 503
    assert raised.value.context == {
        "scope": scope.value,
        "scope_id": scope_id,
        "incident_id": "INC-1",
        "operation": operation,
    }
    assert tenants == ["tenant-a"]


async def test_require_allowed_filters_partition_and_allows_non_blocked_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(
        scalar_row_sets=[
            [
                _row(
                    scope=KillSwitchScope.CAPABILITY,
                    scope_id="email.prepare",
                    mode="writes",
                )
            ]
        ]
    )
    tenants: list[str] = []
    _patch_tenant_sessions(monkeypatch, [session], tenants)

    await _registry().require_allowed(
        tenant_id="tenant-a",
        use_case="report",
        capability="email.prepare",
        operation="execute",
        now=NOW,
    )

    rendered = str(
        session.statements[0].compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "kill_switches.tenant_partition IN ('*', 'tenant-a')" in rendered
    assert "kill_switches.deactivated_at IS NULL" in rendered
    assert "kill_switches.expires_at > '2026-07-24 09:00:00+00:00'" in rendered


async def test_active_and_audit_log_project_rows_and_order_queries() -> None:
    global_row = _row(scope=KillSwitchScope.GLOBAL, scope_id="*", mode="all")
    tenant_row = _row()
    audit_row = _audit_row(tenant_row.switch_id)
    active_session = _Session(scalar_row_sets=[[global_row, tenant_row]])
    audit_session = _Session(scalar_row_sets=[[audit_row]])
    registry = _registry(management_factory=_Factory(active_session, audit_session))

    active = await registry.active(now=NOW)
    audit = await registry.audit_log()

    assert [item.switch_id for item in active] == [
        global_row.switch_id,
        tenant_row.switch_id,
    ]
    assert active[0].scope is KillSwitchScope.GLOBAL
    assert active[1].expires_at == tenant_row.expires_at
    assert audit[0].audit_id == audit_row.audit_id
    assert audit[0].scope is KillSwitchScope.TENANT
    assert audit[0].created_at == NOW
    active_sql = str(
        active_session.statements[1].compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )
    audit_sql = str(
        audit_session.statements[1].compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "ORDER BY kill_switches.activated_at, kill_switches.switch_id" in active_sql
    assert "ORDER BY kill_switch_audit.created_at, kill_switch_audit.audit_id" in audit_sql
    assert active_session.rollbacks == audit_session.rollbacks == 1
    assert active_session.closes == audit_session.closes == 1


def test_mode_blocking_semantics_are_explicit() -> None:
    assert PostgresKillSwitchRegistry._mode_blocks("all", "execute") is True
    assert PostgresKillSwitchRegistry._mode_blocks("writes", "prepare") is True
    assert PostgresKillSwitchRegistry._mode_blocks("writes", "commit") is True
    assert PostgresKillSwitchRegistry._mode_blocks("writes", "write") is True
    assert PostgresKillSwitchRegistry._mode_blocks("writes", "execute") is False
