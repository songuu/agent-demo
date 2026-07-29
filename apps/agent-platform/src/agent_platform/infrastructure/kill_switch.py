"""Audited hierarchical Kill Switch controls.

Queries remain available during broad incidents so operators can inspect state
and preserve evidence. New execution, model calls, tools, and commits fail
closed at the most specific active scope.
"""

from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from agent_platform.application.errors import PlatformError


class KillSwitchScope(enum.StrEnum):
    CAPABILITY = "capability"
    USE_CASE = "use_case"
    TENANT = "tenant"
    ENVIRONMENT = "environment"
    GLOBAL = "global"


@dataclass(slots=True)
class KillSwitchRecord:
    switch_id: UUID
    scope: KillSwitchScope
    scope_id: str
    mode: str
    reason: str
    changed_by: str
    incident_id: str
    activated_at: datetime
    expires_at: datetime | None = None
    deactivated_at: datetime | None = None
    deactivated_by: str | None = None
    deactivation_reason: str | None = None


@dataclass(frozen=True, slots=True)
class KillSwitchAudit:
    audit_id: UUID
    switch_id: UUID
    action: str
    scope: KillSwitchScope
    scope_id: str
    mode: str
    changed_by: str
    reason: str
    incident_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class KillSwitchRegistry:
    def __init__(self, *, environment: str) -> None:
        self._environment = environment
        self._records: dict[UUID, KillSwitchRecord] = {}
        self._audit: list[KillSwitchAudit] = []
        self._lock = asyncio.Lock()

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
        if not all(
            value.strip() for value in (scope_id, reason, changed_by, incident_id)
        ):
            raise ValueError("KILL_SWITCH_AUDIT_FIELDS_REQUIRED")
        activated_at = now or datetime.now(UTC)
        if expires_at is not None and expires_at <= activated_at:
            raise ValueError("KILL_SWITCH_EXPIRY_INVALID")
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
        async with self._lock:
            self._records[record.switch_id] = record
            self._audit.append(
                KillSwitchAudit(
                    audit_id=uuid4(),
                    switch_id=record.switch_id,
                    action="activated",
                    scope=scope,
                    scope_id=scope_id,
                    mode=mode,
                    changed_by=changed_by,
                    reason=reason,
                    incident_id=incident_id,
                    created_at=activated_at,
                )
            )
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
        async with self._lock:
            record = self._records.get(switch_id)
            if record is None:
                raise PlatformError(
                    "NOT_FOUND",
                    "Kill switch was not found",
                    http_status=404,
                )
            if record.deactivated_at is None:
                record.deactivated_at = changed_at
                record.deactivated_by = changed_by
                record.deactivation_reason = reason
                self._audit.append(
                    KillSwitchAudit(
                        audit_id=uuid4(),
                        switch_id=record.switch_id,
                        action="deactivated",
                        scope=record.scope,
                        scope_id=record.scope_id,
                        mode=record.mode,
                        changed_by=changed_by,
                        reason=reason,
                        incident_id=record.incident_id,
                        created_at=changed_at,
                    )
                )
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
        async with self._lock:
            active = [
                record
                for record in self._records.values()
                if record.deactivated_at is None
                and (record.expires_at is None or record.expires_at > current)
            ]
        checks = (
            (
                KillSwitchScope.GLOBAL,
                "*",
                "GLOBAL_KILL_SWITCH_ACTIVE",
            ),
            (
                KillSwitchScope.ENVIRONMENT,
                self._environment,
                "ENVIRONMENT_KILL_SWITCH_ACTIVE",
            ),
            (
                KillSwitchScope.TENANT,
                tenant_id,
                "TENANT_KILL_SWITCH_ACTIVE",
            ),
            (
                KillSwitchScope.USE_CASE,
                use_case,
                "USE_CASE_KILL_SWITCH_ACTIVE",
            ),
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
                    if record.scope == scope
                    and record.scope_id == scope_id
                    and _mode_blocks(record.mode, operation)
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
        async with self._lock:
            return tuple(
                record
                for record in self._records.values()
                if record.deactivated_at is None
                and (record.expires_at is None or record.expires_at > current)
            )

    async def audit_log(self) -> tuple[KillSwitchAudit, ...]:
        async with self._lock:
            return tuple(self._audit)


def _mode_blocks(mode: str, operation: str) -> bool:
    if mode == "all":
        return True
    return operation in {"prepare", "commit", "write"}
