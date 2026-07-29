"""Audited hierarchical Kill Switch registry backed by PostgreSQL."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.kill_switch import (
    KillSwitchAudit,
    KillSwitchRecord,
    KillSwitchScope,
)
from agent_platform.infrastructure.persistence.governance_models import (
    KillSwitchAuditRow,
    ScopedKillSwitch,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)


class PostgresKillSwitchRegistry:
    """Runtime reads use tenant RLS; broad management requires a separate role."""

    def __init__(
        self,
        factory: AsyncSessionFactory,
        *,
        environment: str,
        management_factory: AsyncSessionFactory | None = None,
    ) -> None:
        self._factory = factory
        self._management_factory = management_factory
        self._environment = environment

    async def activate(
        self,
        *,
        scope: KillSwitchScope,
        scope_id: str,
        mode: str,
        reason: str,
        changed_by: str,
        incident_id: str,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> KillSwitchRecord:
        if mode not in {"writes", "all"}:
            raise ValueError("KILL_SWITCH_MODE_INVALID")
        if not all(value.strip() for value in (scope_id, reason, changed_by, incident_id)):
            raise ValueError("KILL_SWITCH_AUDIT_FIELDS_REQUIRED")
        activated_at = now or datetime.now(UTC)
        if expires_at is not None and expires_at <= activated_at:
            raise ValueError("KILL_SWITCH_EXPIRY_INVALID")
        if scope is KillSwitchScope.ENVIRONMENT and scope_id != self._environment:
            raise ValueError("KILL_SWITCH_ENVIRONMENT_MISMATCH")

        record = KillSwitchRecord(
            switch_id=uuid4(),
            scope=scope,
            scope_id=scope_id,
            mode=mode,
            reason=reason,
            changed_by=changed_by,
            incident_id=incident_id,
            activated_at=activated_at,
            expires_at=expires_at,
        )
        partition = scope_id if scope is KillSwitchScope.TENANT else "*"
        context = (
            tenant_session(self._factory, partition)
            if scope is KillSwitchScope.TENANT
            else self._management_session()
        )
        async with context as session:
            session.add(self._database_record(record, partition))
            await session.flush()
            session.add(
                self._database_audit(
                    record,
                    partition=partition,
                    action="activated",
                    changed_by=changed_by,
                    reason=reason,
                    created_at=activated_at,
                )
            )
            await session.commit()
        return record

    async def deactivate(
        self,
        switch_id: UUID,
        *,
        changed_by: str,
        reason: str,
        now: datetime | None = None,
    ) -> KillSwitchRecord:
        if not changed_by.strip() or not reason.strip():
            raise ValueError("KILL_SWITCH_AUDIT_FIELDS_REQUIRED")
        changed_at = now or datetime.now(UTC)
        async with self._management_session() as session:
            row = await session.scalar(
                select(ScopedKillSwitch)
                .where(ScopedKillSwitch.switch_id == switch_id)
                .with_for_update()
            )
            if row is None:
                raise PlatformError(
                    "NOT_FOUND",
                    "Kill switch was not found",
                    http_status=404,
                )
            if row.deactivated_at is None:
                row.deactivated_at = changed_at
                row.deactivated_by = changed_by
                row.deactivation_reason = reason
                session.add(
                    KillSwitchAuditRow(
                        audit_id=uuid4(),
                        switch_id=row.switch_id,
                        tenant_partition=row.tenant_partition,
                        action="deactivated",
                        scope=row.scope,
                        scope_id=row.scope_id,
                        mode=row.mode,
                        changed_by=changed_by,
                        reason=reason,
                        incident_id=row.incident_id,
                        created_at=changed_at,
                    )
                )
            record = self._record(row)
            await session.commit()
            return record

    async def require_allowed(
        self,
        *,
        tenant_id: str,
        use_case: str,
        capability: str,
        operation: str,
        now: datetime | None = None,
    ) -> None:
        if operation == "query":
            return
        current = now or datetime.now(UTC)
        async with tenant_session(self._factory, tenant_id) as session:
            rows = (
                await session.scalars(
                    select(ScopedKillSwitch).where(
                        ScopedKillSwitch.tenant_partition.in_(("*", tenant_id)),
                        ScopedKillSwitch.deactivated_at.is_(None),
                        (
                            ScopedKillSwitch.expires_at.is_(None)
                            | (ScopedKillSwitch.expires_at > current)
                        ),
                    )
                )
            ).all()
            active = tuple(self._record(row) for row in rows)

        checks = (
            (KillSwitchScope.GLOBAL, "*", "GLOBAL_KILL_SWITCH_ACTIVE"),
            (
                KillSwitchScope.ENVIRONMENT,
                self._environment,
                "ENVIRONMENT_KILL_SWITCH_ACTIVE",
            ),
            (KillSwitchScope.TENANT, tenant_id, "TENANT_KILL_SWITCH_ACTIVE"),
            (KillSwitchScope.USE_CASE, use_case, "USE_CASE_KILL_SWITCH_ACTIVE"),
            (
                KillSwitchScope.CAPABILITY,
                capability,
                "CAPABILITY_KILL_SWITCH_ACTIVE",
            ),
        )
        for scope, scope_id, code in checks:
            match = next(
                (
                    record
                    for record in active
                    if record.scope is scope
                    and record.scope_id == scope_id
                    and self._mode_blocks(record.mode, operation)
                ),
                None,
            )
            if match is not None:
                raise PlatformError(
                    code,
                    f"{scope.value} execution is disabled by an active Kill Switch",
                    http_status=503,
                    context={
                        "scope": scope.value,
                        "scope_id": scope_id,
                        "incident_id": match.incident_id,
                        "operation": operation,
                    },
                )

    async def active(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[KillSwitchRecord, ...]:
        current = now or datetime.now(UTC)
        async with self._management_session() as session:
            rows = (
                await session.scalars(
                    select(ScopedKillSwitch)
                    .where(
                        ScopedKillSwitch.deactivated_at.is_(None),
                        (
                            ScopedKillSwitch.expires_at.is_(None)
                            | (ScopedKillSwitch.expires_at > current)
                        ),
                    )
                    .order_by(
                        ScopedKillSwitch.activated_at,
                        ScopedKillSwitch.switch_id,
                    )
                )
            ).all()
            return tuple(self._record(row) for row in rows)

    async def audit_log(self) -> tuple[KillSwitchAudit, ...]:
        async with self._management_session() as session:
            rows = (
                await session.scalars(
                    select(KillSwitchAuditRow).order_by(
                        KillSwitchAuditRow.created_at,
                        KillSwitchAuditRow.audit_id,
                    )
                )
            ).all()
            return tuple(self._audit(row) for row in rows)

    @asynccontextmanager
    async def _management_session(self) -> AsyncIterator[AsyncSession]:
        if self._management_factory is None:
            raise PlatformError(
                "KILL_SWITCH_MANAGEMENT_ROLE_REQUIRED",
                "Broad Kill Switch management requires the dedicated database role",
                http_status=503,
            )
        session = self._management_factory()
        try:
            await session.begin()
            await session.execute(text("SELECT set_config('app.tenant_id', '*', true)"))
            yield session
        finally:
            if session.in_transaction():
                await session.rollback()
            await session.close()

    @staticmethod
    def _database_record(record: KillSwitchRecord, partition: str) -> ScopedKillSwitch:
        return ScopedKillSwitch(
            switch_id=record.switch_id,
            tenant_partition=partition,
            scope=record.scope.value,
            scope_id=record.scope_id,
            mode=record.mode,
            reason=record.reason,
            changed_by=record.changed_by,
            incident_id=record.incident_id,
            activated_at=record.activated_at,
            expires_at=record.expires_at,
            deactivated_at=record.deactivated_at,
            deactivated_by=record.deactivated_by,
            deactivation_reason=record.deactivation_reason,
        )

    @staticmethod
    def _database_audit(
        record: KillSwitchRecord,
        *,
        partition: str,
        action: str,
        changed_by: str,
        reason: str,
        created_at: datetime,
    ) -> KillSwitchAuditRow:
        return KillSwitchAuditRow(
            audit_id=uuid4(),
            switch_id=record.switch_id,
            tenant_partition=partition,
            action=action,
            scope=record.scope.value,
            scope_id=record.scope_id,
            mode=record.mode,
            changed_by=changed_by,
            reason=reason,
            incident_id=record.incident_id,
            created_at=created_at,
        )

    @staticmethod
    def _record(row: ScopedKillSwitch) -> KillSwitchRecord:
        return KillSwitchRecord(
            switch_id=row.switch_id,
            scope=KillSwitchScope(row.scope),
            scope_id=row.scope_id,
            mode=row.mode,
            reason=row.reason,
            changed_by=row.changed_by,
            incident_id=row.incident_id,
            activated_at=row.activated_at,
            expires_at=row.expires_at,
            deactivated_at=row.deactivated_at,
            deactivated_by=row.deactivated_by,
            deactivation_reason=row.deactivation_reason,
        )

    @staticmethod
    def _audit(row: KillSwitchAuditRow) -> KillSwitchAudit:
        return KillSwitchAudit(
            audit_id=row.audit_id,
            switch_id=row.switch_id,
            action=row.action,
            scope=KillSwitchScope(row.scope),
            scope_id=row.scope_id,
            mode=row.mode,
            changed_by=row.changed_by,
            reason=row.reason,
            incident_id=row.incident_id,
            created_at=row.created_at,
        )

    @staticmethod
    def _mode_blocks(mode: str, operation: str) -> bool:
        if mode == "all":
            return True
        return operation in {"prepare", "commit", "write"}
