"""Repository adapters that keep database invariants inside one transaction."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import Select, TextClause, func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.infrastructure.persistence.models import (
    ActionStatus,
    AgentRun,
    IdempotencyRecord,
    OutboxEvent,
    PreparedAction,
    RunEvent,
    RunStatus,
)


class OptimisticConcurrencyError(RuntimeError):
    """Raised when a snapshot version changed before the requested update."""


class IdempotencyConflictError(RuntimeError):
    """Raised when a key is reused for a different request payload."""


def build_transition_statement(
    *,
    run_id: str | uuid.UUID,
    tenant_id: str,
    expected: Sequence[RunStatus],
    target: RunStatus,
    expected_version: int,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    correlation_id: str,
    payload: Mapping[str, Any],
    payload_hash: str,
) -> TextClause:
    """Build the call to the migration-owned atomic transition function."""
    return text(
        """
        SELECT *
        FROM transition_run(
            p_run_id := CAST(:p_run_id AS uuid),
            p_tenant_id := :p_tenant_id,
            p_expected := CAST(:p_expected AS run_status[]),
            p_target := CAST(:p_target AS run_status),
            p_expected_version := :p_expected_version,
            p_event_type := :p_event_type,
            p_actor_type := :p_actor_type,
            p_actor_id := :p_actor_id,
            p_correlation_id := :p_correlation_id,
            p_payload := CAST(:p_payload AS jsonb),
            p_payload_hash := :p_payload_hash
        )
        """
    ).bindparams(
        p_run_id=str(run_id),
        p_tenant_id=tenant_id,
        p_expected=[status.value for status in expected],
        p_target=target.value,
        p_expected_version=expected_version,
        p_event_type=event_type,
        p_actor_type=actor_type,
        p_actor_id=actor_id,
        p_correlation_id=correlation_id,
        p_payload=dict(payload),
        p_payload_hash=payload_hash,
    )


class RunRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, run: AgentRun) -> None:
        self._session.add(run)
        await self._session.flush()

    async def get(self, run_id: uuid.UUID, tenant_id: str) -> AgentRun | None:
        statement: Select[tuple[AgentRun]] = select(AgentRun).where(
            AgentRun.run_id == run_id,
            AgentRun.tenant_id == tenant_id,
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def update_snapshot(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        expected_version: int,
        values: Mapping[str, Any],
    ) -> int:
        protected = {"run_id", "tenant_id", "created_at", "version"}
        if protected.intersection(values):
            raise ValueError("snapshot update contains protected fields")
        statement = (
            update(AgentRun)
            .where(
                AgentRun.run_id == run_id,
                AgentRun.tenant_id == tenant_id,
                AgentRun.version == expected_version,
            )
            .values(**dict(values), version=AgentRun.version + 1, updated_at=func.now())
            .returning(AgentRun.version)
        )
        version = await self._session.scalar(statement)
        if version is None:
            raise OptimisticConcurrencyError(f"run {run_id} version {expected_version} is stale")
        return int(version)

    async def transition(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        expected: Sequence[RunStatus],
        target: RunStatus,
        expected_version: int,
        event_type: str,
        actor_type: str,
        actor_id: str | None,
        correlation_id: str,
        payload: Mapping[str, Any],
        payload_hash: str,
    ) -> Mapping[str, Any]:
        if not expected:
            raise ValueError("expected statuses cannot be empty")
        result = await self._session.execute(
            build_transition_statement(
                run_id=run_id,
                tenant_id=tenant_id,
                expected=expected,
                target=target,
                expected_version=expected_version,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                correlation_id=correlation_id,
                payload=payload,
                payload_hash=payload_hash,
            )
        )
        row = result.mappings().one()
        return dict(row)

    async def append_event_and_outbox(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str | None,
        correlation_id: str,
        payload: dict[str, Any],
        payload_hash: str,
        event_key: str,
    ) -> RunEvent:
        # The snapshot lock serializes per-Run sequence allocation without MAX races.
        await self._session.execute(
            select(AgentRun.run_id)
            .where(AgentRun.run_id == run_id, AgentRun.tenant_id == tenant_id)
            .with_for_update()
        )
        next_sequence = await self._session.scalar(
            select(func.coalesce(func.max(RunEvent.sequence_no), 0) + 1).where(
                RunEvent.run_id == run_id
            )
        )
        event = RunEvent(
            run_id=run_id,
            tenant_id=tenant_id,
            sequence_no=int(next_sequence or 1),
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            correlation_id=correlation_id,
            payload=payload,
            payload_hash=payload_hash,
        )
        self._session.add_all(
            [
                event,
                OutboxEvent(
                    tenant_id=tenant_id,
                    aggregate_type="run",
                    aggregate_id=str(run_id),
                    event_key=event_key,
                    event_type=event_type,
                    payload=payload,
                    payload_hash=payload_hash,
                ),
            ]
        )
        await self._session.flush()
        return event


class ActionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, action: PreparedAction) -> None:
        self._session.add(action)
        await self._session.flush()

    async def get_for_commit(
        self,
        action_id: uuid.UUID,
        tenant_id: str,
    ) -> PreparedAction | None:
        """Lock an action before reauthorization and external commit."""
        statement: Select[tuple[PreparedAction]] = (
            select(PreparedAction)
            .where(
                PreparedAction.action_id == action_id,
                PreparedAction.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def mark_committing(
        self,
        *,
        action_id: uuid.UUID,
        tenant_id: str,
        expected_version: int,
        expected_statuses: Sequence[ActionStatus] = (
            ActionStatus.APPROVED,
            ActionStatus.UNKNOWN,
        ),
    ) -> int:
        statement = (
            update(PreparedAction)
            .where(
                PreparedAction.action_id == action_id,
                PreparedAction.tenant_id == tenant_id,
                PreparedAction.version == expected_version,
                PreparedAction.status.in_(expected_statuses),
                PreparedAction.expires_at > func.now(),
            )
            .values(
                status=ActionStatus.COMMITTING,
                committing_at=func.now(),
                updated_at=func.now(),
                version=PreparedAction.version + 1,
            )
            .returning(PreparedAction.version)
        )
        version = await self._session.scalar(statement)
        if version is None:
            raise OptimisticConcurrencyError(f"action {action_id} cannot be acquired for commit")
        return int(version)


class IdempotencyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self,
        *,
        tenant_id: str,
        scope: str,
        key: str,
    ) -> IdempotencyRecord | None:
        return await self._session.get(
            IdempotencyRecord,
            {
                "tenant_id": tenant_id,
                "scope": scope,
                "idempotency_key": key,
            },
        )

    async def claim(
        self,
        *,
        tenant_id: str,
        scope: str,
        key: str,
        request_hash: str,
        resource_type: str,
        resource_id: str,
        expires_at: datetime,
    ) -> bool:
        statement = (
            insert(IdempotencyRecord)
            .values(
                tenant_id=tenant_id,
                scope=scope,
                idempotency_key=key,
                request_hash=request_hash,
                resource_type=resource_type,
                resource_id=resource_id,
                expires_at=expires_at,
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "scope", "idempotency_key"])
            .returning(IdempotencyRecord.idempotency_key)
        )
        inserted = await self._session.scalar(statement)
        if inserted is not None:
            return True
        existing = await self.get(tenant_id=tenant_id, scope=scope, key=key)
        if existing is not None and existing.request_hash != request_hash:
            raise IdempotencyConflictError(
                f"idempotency key {key!r} was used with another request hash"
            )
        return False
