"""Concurrency-safe in-memory adapters for tests and local reference flows.

The implementation mirrors production repository semantics: tenant lookups do
not disclose cross-tenant resources, request/action idempotency is scoped, and
updates use optimistic versions plus action-level locks.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID

from agent_platform.application.errors import Conflict, NotFound
from agent_platform.application.records import (
    ActionAuditTransaction,
    ActionRecord,
    ArtifactRecord,
    AuditEvent,
    CapabilityRecord,
    EventRecord,
    PlanExecutionRecord,
    RunRecord,
    TaskExecutionRecord,
    ToolInvocationRecord,
    utcnow,
)
from agent_platform.domain.hashing import canonical_json, payload_hash


class _InMemoryRunTrajectoryTransaction:
    """Run-lock-scoped transaction used by the durable trajectory guard."""

    def __init__(self, repository: InMemoryRunRepository, run: RunRecord) -> None:
        self._repository = repository
        self.run = copy.deepcopy(run)

    @property
    def events(self) -> tuple[EventRecord, ...]:
        return tuple(copy.deepcopy(event) for event in self._repository._events[self.run.run_id])

    async def append_event(self, event: AuditEvent) -> EventRecord:
        stored = self._repository._append_event_locked(self.run, event)
        return copy.deepcopy(stored)

    async def save_run(self, expected_version: int) -> RunRecord:
        current = self._repository._runs.get(self.run.run_id)
        if current is None or current.tenant_id != self.run.tenant_id:
            raise NotFound("run", str(self.run.run_id))
        if current.version != expected_version:
            raise Conflict(
                "OPTIMISTIC_LOCK_CONFLICT",
                "Run version changed concurrently",
                run_id=str(self.run.run_id),
                expected_version=expected_version,
                actual_version=current.version,
            )
        stored = copy.deepcopy(self.run)
        stored.version = expected_version + 1
        self._repository._runs[self.run.run_id] = stored
        self.run = copy.deepcopy(stored)
        return copy.deepcopy(stored)


class InMemoryRunRepository:
    def __init__(self) -> None:
        self._runs: dict[UUID, RunRecord] = {}
        self._idempotency: dict[tuple[str, str], UUID] = {}
        self._events: dict[UUID, list[EventRecord]] = {}
        self._lock = asyncio.Lock()

    async def create_once(self, run: RunRecord) -> tuple[RunRecord, bool]:
        key = (run.tenant_id, run.idempotency_key)
        async with self._lock:
            existing_id = self._idempotency.get(key)
            if existing_id is not None:
                existing = self._runs[existing_id]
                if existing.request_hash != run.request_hash:
                    raise Conflict(
                        "IDEMPOTENCY_KEY_REUSED",
                        "Idempotency key was reused for a different request",
                        idempotency_key=run.idempotency_key,
                    )
                return copy.deepcopy(existing), False
            self._runs[run.run_id] = copy.deepcopy(run)
            self._idempotency[key] = run.run_id
            self._events[run.run_id] = []
            return copy.deepcopy(run), True

    async def create_once_with_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, bool, EventRecord | None]:
        key = (run.tenant_id, run.idempotency_key)
        async with self._lock:
            existing_id = self._idempotency.get(key)
            if existing_id is not None:
                existing = self._runs[existing_id]
                if existing.request_hash != run.request_hash:
                    raise Conflict(
                        "IDEMPOTENCY_KEY_REUSED",
                        "Idempotency key was reused for a different request",
                        idempotency_key=run.idempotency_key,
                    )
                return copy.deepcopy(existing), False, None
            audit_event = AuditEvent(
                event_type=event_type,
                payload=dict(payload),
                correlation_id=correlation_id,
                actor_id=run.principal_id,
            )
            # Validate the event before mutating any in-memory snapshot.
            payload_hash(audit_event.payload)
            self._runs[run.run_id] = copy.deepcopy(run)
            self._idempotency[key] = run.run_id
            self._events[run.run_id] = []
            event = self._append_event_locked(run, audit_event)
            return copy.deepcopy(run), True, copy.deepcopy(event)

    async def get(self, run_id: UUID, tenant_id: str) -> RunRecord:
        run = self._runs.get(run_id)
        if run is None or run.tenant_id != tenant_id:
            raise NotFound("run", str(run_id))
        return copy.deepcopy(run)

    async def save(self, run: RunRecord, expected_version: int) -> RunRecord:
        async with self._lock:
            current = self._runs.get(run.run_id)
            if current is None or current.tenant_id != run.tenant_id:
                raise NotFound("run", str(run.run_id))
            if current.version != expected_version:
                raise Conflict(
                    "OPTIMISTIC_LOCK_CONFLICT",
                    "Run version changed concurrently",
                    run_id=str(run.run_id),
                    expected_version=expected_version,
                    actual_version=current.version,
                )
            stored = copy.deepcopy(run)
            stored.version = expected_version + 1
            self._runs[run.run_id] = stored
            return copy.deepcopy(stored)

    async def save_with_event(
        self,
        run: RunRecord,
        expected_version: int,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> tuple[RunRecord, EventRecord]:
        async with self._lock:
            current = self._runs.get(run.run_id)
            if current is None or current.tenant_id != run.tenant_id:
                raise NotFound("run", str(run.run_id))
            if current.version != expected_version:
                raise Conflict(
                    "OPTIMISTIC_LOCK_CONFLICT",
                    "Run version changed concurrently",
                    run_id=str(run.run_id),
                )
            audit_event = AuditEvent(
                event_type=event_type,
                payload=dict(payload),
                correlation_id=correlation_id,
                actor_id=run.principal_id,
            )
            payload_hash(audit_event.payload)
            stored = copy.deepcopy(run)
            stored.version = expected_version + 1
            self._runs[run.run_id] = stored
            event = self._append_event_locked(stored, audit_event)
            return copy.deepcopy(stored), copy.deepcopy(event)

    async def append_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> EventRecord:
        async with self._lock:
            current = self._runs.get(run.run_id)
            if current is None or current.tenant_id != run.tenant_id:
                raise NotFound("run", str(run.run_id))
            event = self._append_event_locked(
                current,
                AuditEvent(
                    event_type=event_type,
                    payload=dict(payload),
                    correlation_id=correlation_id,
                    actor_id=run.principal_id,
                ),
            )
            return copy.deepcopy(event)

    def _append_event_locked(self, run: RunRecord, event: AuditEvent) -> EventRecord:
        records = self._events[run.run_id]
        sequence = len(records) + 1
        digest = payload_hash(event.payload)
        stored = EventRecord(
            event_id=f"{run.run_id}:{sequence}",
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            sequence_no=sequence,
            event_type=event.event_type,
            payload=copy.deepcopy(event.payload),
            correlation_id=event.correlation_id,
            actor_type=event.actor_type,
            actor_id=event.actor_id or run.principal_id,
            task_id=event.task_id,
            action_id=event.action_id,
            payload_hash=digest,
        )
        records.append(stored)
        return stored

    async def events_after(
        self, run_id: UUID, tenant_id: str, sequence_no: int
    ) -> Sequence[EventRecord]:
        await self.get(run_id, tenant_id)
        return tuple(
            copy.deepcopy(event)
            for event in self._events.get(run_id, ())
            if event.sequence_no > sequence_no
        )

    @asynccontextmanager
    async def trajectory_transaction(self, run_id: UUID, tenant_id: str) -> Any:
        """Atomically persist candidate, decision, and an optional Run state change."""
        async with self._lock:
            current = self._runs.get(run_id)
            if current is None or current.tenant_id != tenant_id:
                raise NotFound("run", str(run_id))
            original_run = copy.deepcopy(current)
            original_events = copy.deepcopy(self._events[run_id])
            transaction = _InMemoryRunTrajectoryTransaction(self, current)
            try:
                yield transaction
            except BaseException:
                self._runs[run_id] = original_run
                self._events[run_id] = original_events
                raise


class InMemoryActionRepository:
    def __init__(self, runs: InMemoryRunRepository, audit: Any) -> None:
        self._runs = runs
        self._audit = audit
        self._actions: dict[UUID, ActionRecord] = {}
        self._idempotency: dict[tuple[str, str], UUID] = {}
        self._locks: dict[UUID, asyncio.Lock] = {}
        self._index_lock = asyncio.Lock()

    async def create_once(self, action: ActionRecord) -> tuple[ActionRecord, bool]:
        key = (action.tenant_id, action.idempotency_key)
        async with self._index_lock:
            existing_id = self._idempotency.get(key)
            if existing_id is not None:
                existing = self._actions[existing_id]
                if existing.payload_hash != action.payload_hash:
                    raise Conflict(
                        "ACTION_IDEMPOTENCY_CONFLICT",
                        "Action idempotency key was reused with a different payload",
                        idempotency_key=action.idempotency_key,
                    )
                return copy.deepcopy(existing), False
            self._actions[action.action_id] = copy.deepcopy(action)
            self._idempotency[key] = action.action_id
            self._locks[action.action_id] = asyncio.Lock()
            return copy.deepcopy(action), True

    async def create_once_with_event(
        self,
        action: ActionRecord,
        event: AuditEvent,
        invocation: ToolInvocationRecord | None = None,
    ) -> tuple[ActionRecord, bool, EventRecord | None]:
        if event.action_id not in {None, action.action_id}:
            raise ValueError("AUDIT_EVENT_ACTION_MISMATCH")
        if invocation is not None and invocation.run_id != action.run_id:
            raise ValueError("TOOL_INVOCATION_RUN_MISMATCH")
        payload_hash(event.payload)
        key = (action.tenant_id, action.idempotency_key)
        async with self._index_lock:
            existing_id = self._idempotency.get(key)
            if existing_id is not None:
                existing = self._actions[existing_id]
                if existing.payload_hash != action.payload_hash:
                    raise Conflict(
                        "ACTION_IDEMPOTENCY_CONFLICT",
                        "Action idempotency key was reused with a different payload",
                        idempotency_key=action.idempotency_key,
                    )
                return copy.deepcopy(existing), False, None
            async with self._runs._lock:
                run = self._runs._runs.get(action.run_id)
                if run is None or run.tenant_id != action.tenant_id:
                    raise NotFound("run", str(action.run_id))
                if invocation is not None and invocation.invocation_id in self._audit._tools:
                    raise Conflict(
                        "TOOL_INVOCATION_CONFLICT",
                        "Tool invocation identifier already exists",
                    )
                self._actions[action.action_id] = copy.deepcopy(action)
                self._idempotency[key] = action.action_id
                self._locks[action.action_id] = asyncio.Lock()
                if invocation is not None:
                    self._audit._record_tool_locked(invocation)
                recorded = self._runs._append_event_locked(
                    run,
                    AuditEvent(
                        event_type=event.event_type,
                        payload=event.payload,
                        correlation_id=event.correlation_id,
                        actor_type=event.actor_type,
                        actor_id=event.actor_id,
                        task_id=event.task_id,
                        action_id=event.action_id or action.action_id,
                    ),
                )
                return copy.deepcopy(action), True, copy.deepcopy(recorded)

    async def get(self, action_id: UUID, tenant_id: str) -> ActionRecord:
        action = self._actions.get(action_id)
        if action is None or action.tenant_id != tenant_id:
            raise NotFound("action", str(action_id))
        return copy.deepcopy(action)

    @asynccontextmanager
    async def get_for_update(self, action_id: UUID, tenant_id: str) -> Any:
        await self.get(action_id, tenant_id)
        lock = self._locks[action_id]
        async with lock:
            current = self._actions[action_id]
            working = copy.deepcopy(current)
            try:
                yield working
            finally:
                # UNKNOWN/EXPIRED are durable recovery checkpoints even when
                # the service raises the exception that reports the outcome.
                working.version = current.version + 1
                self._actions[action_id] = copy.deepcopy(working)

    @asynccontextmanager
    async def transaction(self, action_id: UUID, tenant_id: str) -> Any:
        await self.get(action_id, tenant_id)
        lock = self._locks[action_id]
        async with lock:
            current = self._actions[action_id]
            working = copy.deepcopy(current)
            baseline = copy.deepcopy(current)
            transaction = ActionAuditTransaction(action=working)
            try:
                yield transaction
            except Exception:
                await self._persist_audit_transaction(transaction, baseline, current.version)
                raise
            else:
                await self._persist_audit_transaction(transaction, baseline, current.version)

    async def _persist_audit_transaction(
        self,
        transaction: ActionAuditTransaction,
        baseline: ActionRecord,
        expected_version: int,
    ) -> None:
        action = transaction.action
        for event in transaction.events:
            payload_hash(event.payload)
        async with self._runs._lock:
            run = self._runs._runs.get(action.run_id)
            if run is None or run.tenant_id != action.tenant_id:
                raise NotFound("run", str(action.run_id))
            duplicate = next(
                (
                    invocation.invocation_id
                    for invocation in transaction.tool_invocations
                    if invocation.invocation_id in self._audit._tools
                ),
                None,
            )
            if duplicate is not None:
                raise Conflict(
                    "TOOL_INVOCATION_CONFLICT",
                    "Tool invocation identifier already exists",
                )
            if action != baseline:
                action.version = expected_version + 1
                action.updated_at = utcnow()
                self._actions[action.action_id] = copy.deepcopy(action)
            for invocation in transaction.tool_invocations:
                self._audit._record_tool_locked(invocation)
            for event in transaction.events:
                self._runs._append_event_locked(
                    run,
                    AuditEvent(
                        event_type=event.event_type,
                        payload=event.payload,
                        correlation_id=event.correlation_id,
                        actor_type=event.actor_type,
                        actor_id=event.actor_id,
                        task_id=event.task_id,
                        action_id=event.action_id or action.action_id,
                    ),
                )

    async def list_for_run(self, run_id: UUID, tenant_id: str) -> Sequence[ActionRecord]:
        return tuple(
            copy.deepcopy(action)
            for action in self._actions.values()
            if action.run_id == run_id and action.tenant_id == tenant_id
        )

    async def save(self, action: ActionRecord, expected_version: int) -> ActionRecord:
        async with self._locks[action.action_id]:
            current = self._actions.get(action.action_id)
            if current is None or current.tenant_id != action.tenant_id:
                raise NotFound("action", str(action.action_id))
            if current.version != expected_version:
                raise Conflict(
                    "OPTIMISTIC_LOCK_CONFLICT",
                    "Action version changed concurrently",
                    action_id=str(action.action_id),
                )
            stored = copy.deepcopy(action)
            stored.version = expected_version + 1
            self._actions[action.action_id] = stored
            return copy.deepcopy(stored)


class InMemoryArtifactStore:
    def __init__(self) -> None:
        self._artifacts: dict[UUID, ArtifactRecord] = {}
        self._lock = asyncio.Lock()

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        async with self._lock:
            existing = self._artifacts.get(artifact.artifact_id)
            if existing is not None and existing.tenant_id != artifact.tenant_id:
                raise Conflict(
                    "ARTIFACT_TENANT_CONFLICT",
                    "Artifact identifier belongs to another tenant",
                    artifact_id=str(artifact.artifact_id),
                )
            self._artifacts[artifact.artifact_id] = copy.deepcopy(artifact)
        return copy.deepcopy(artifact)

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        async with self._lock:
            artifact = self._artifacts.get(artifact_id)
            if (
                artifact is None
                or artifact.tenant_id != tenant_id
                or artifact.deleted_at is not None
                or self._is_expired(artifact)
            ):
                raise NotFound("artifact", str(artifact_id))
            return copy.deepcopy(artifact)

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        async with self._lock:
            artifact = self._artifacts.get(artifact_id)
            if artifact is None:
                return
            if artifact.tenant_id != tenant_id:
                raise NotFound("artifact", str(artifact_id))
            if artifact.deleted_at is not None:
                return
            updated = copy.deepcopy(artifact)
            updated.deleted_at = utcnow()
            self._artifacts[artifact_id] = updated

    @staticmethod
    def _is_expired(artifact: ArtifactRecord) -> bool:
        expires_at = artifact.expires_at
        if expires_at is None:
            return False
        if expires_at.tzinfo is None:
            return True
        return expires_at <= utcnow()


class InMemoryCapabilityStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], CapabilityRecord] = {}
        self._lock = asyncio.Lock()

    async def register(self, tenant_id: str, record: CapabilityRecord) -> None:
        async with self._lock:
            self._records[(tenant_id, record.name)] = copy.deepcopy(record)

    async def list(self, tenant_id: str) -> Sequence[CapabilityRecord]:
        async with self._lock:
            visible = {
                name: copy.deepcopy(value)
                for (record_tenant, name), value in self._records.items()
                if record_tenant == "*"
            }
            visible.update(
                {
                    name: copy.deepcopy(value)
                    for (record_tenant, name), value in self._records.items()
                    if record_tenant == tenant_id
                }
            )
            return tuple(visible[name] for name in sorted(visible))

    async def set_enabled(
        self, tenant_id: str, name: str, enabled: bool, reason: str | None
    ) -> CapabilityRecord:
        async with self._lock:
            key = (tenant_id, name)
            fallback = ("*", name)
            existing = self._records.get(key) or self._records.get(fallback)
            if existing is None:
                raise NotFound("capability", name)
            updated = copy.deepcopy(existing)
            updated.enabled = enabled
            updated.disabled_reason = None if enabled else reason
            self._records[key] = updated
            return copy.deepcopy(updated)


class InMemoryAuditRepository:
    """Local counterpart of the production execution/audit repository."""

    def __init__(self, runs: InMemoryRunRepository) -> None:
        self._runs = runs
        self._plans: dict[tuple[UUID, int], PlanExecutionRecord] = {}
        self._tasks: dict[UUID, TaskExecutionRecord] = {}
        self._tools: dict[UUID, ToolInvocationRecord] = {}
        self._actions: InMemoryActionRepository | None = None
        self._artifacts: InMemoryArtifactStore | None = None

    def bind(
        self,
        actions: InMemoryActionRepository,
        artifacts: InMemoryArtifactStore,
    ) -> None:
        self._actions = actions
        self._artifacts = artifacts

    async def save_plan_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        plan: PlanExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]:
        payload_hash(event.payload)
        async with self._runs._lock:
            current = self._runs._runs.get(run.run_id)
            if current is None or current.tenant_id != run.tenant_id:
                raise NotFound("run", str(run.run_id))
            if current.version != expected_version:
                raise Conflict("OPTIMISTIC_LOCK_CONFLICT", "Run version changed concurrently")
            key = (plan.run_id, plan.plan_version)
            existing = self._plans.get(key)
            if existing is not None and existing.plan_hash != plan.plan_hash:
                raise Conflict(
                    "PLAN_VERSION_CONFLICT",
                    "Plan version already exists with a different hash",
                )
            stored = copy.deepcopy(run)
            stored.version = expected_version + 1
            self._runs._runs[run.run_id] = stored
            self._plans[key] = copy.deepcopy(plan)
            recorded = self._runs._append_event_locked(stored, event)
            return copy.deepcopy(stored), copy.deepcopy(recorded)

    async def start_task(
        self,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> EventRecord | None:
        payload_hash(event.payload)
        async with self._runs._lock:
            run = self._runs._runs.get(execution.run_id)
            if run is None or run.tenant_id != execution.tenant_id:
                raise NotFound("run", str(execution.run_id))
            duplicate = next(
                (
                    item
                    for item in self._tasks.values()
                    if (
                        item.run_id,
                        item.plan_version,
                        item.task_id,
                        item.attempt,
                    )
                    == (
                        execution.run_id,
                        execution.plan_version,
                        execution.task_id,
                        execution.attempt,
                    )
                ),
                None,
            )
            if duplicate is not None:
                return None
            self._tasks[execution.task_execution_id] = copy.deepcopy(execution)
            recorded = self._runs._append_event_locked(run, event)
            return copy.deepcopy(recorded)

    async def complete_task_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]:
        payload_hash(event.payload)
        async with self._runs._lock:
            current = self._runs._runs.get(run.run_id)
            if current is None or current.tenant_id != run.tenant_id:
                raise NotFound("run", str(run.run_id))
            if current.version != expected_version:
                raise Conflict("OPTIMISTIC_LOCK_CONFLICT", "Run version changed concurrently")
            if execution.task_execution_id not in self._tasks:
                raise NotFound("task_execution", str(execution.task_execution_id))
            stored = copy.deepcopy(run)
            stored.version = expected_version + 1
            self._runs._runs[run.run_id] = stored
            self._tasks[execution.task_execution_id] = copy.deepcopy(execution)
            recorded = self._runs._append_event_locked(stored, event)
            return copy.deepcopy(stored), copy.deepcopy(recorded)

    async def finish_task(
        self,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> EventRecord:
        payload_hash(event.payload)
        async with self._runs._lock:
            run = self._runs._runs.get(execution.run_id)
            if run is None or run.tenant_id != execution.tenant_id:
                raise NotFound("run", str(execution.run_id))
            if execution.task_execution_id not in self._tasks:
                raise NotFound("task_execution", str(execution.task_execution_id))
            self._tasks[execution.task_execution_id] = copy.deepcopy(execution)
            recorded = self._runs._append_event_locked(run, event)
            return copy.deepcopy(recorded)

    async def record_tool(
        self,
        invocation: ToolInvocationRecord,
        event: AuditEvent,
    ) -> EventRecord:
        payload_hash(event.payload)
        async with self._runs._lock:
            run = self._runs._runs.get(invocation.run_id)
            if run is None or run.tenant_id != invocation.tenant_id:
                raise NotFound("run", str(invocation.run_id))
            self._record_tool_locked(invocation)
            recorded = self._runs._append_event_locked(run, event)
            return copy.deepcopy(recorded)

    def _record_tool_locked(self, invocation: ToolInvocationRecord) -> None:
        if invocation.invocation_id in self._tools:
            raise Conflict(
                "TOOL_INVOCATION_CONFLICT",
                "Tool invocation identifier already exists",
            )
        self._tools[invocation.invocation_id] = copy.deepcopy(invocation)

    async def export_run(self, run_id: UUID, tenant_id: str) -> Mapping[str, Any]:
        run = await self._runs.get(run_id, tenant_id)
        if self._actions is None or self._artifacts is None:
            raise RuntimeError("AUDIT_REPOSITORY_NOT_BOUND")
        actions = await self._actions.list_for_run(run_id, tenant_id)
        events = await self._runs.events_after(run_id, tenant_id, 0)
        plans = sorted(
            (
                copy.deepcopy(value)
                for value in self._plans.values()
                if value.run_id == run_id and value.tenant_id == tenant_id
            ),
            key=lambda value: value.plan_version,
        )
        tasks = sorted(
            (
                copy.deepcopy(value)
                for value in self._tasks.values()
                if value.run_id == run_id and value.tenant_id == tenant_id
            ),
            key=lambda value: (value.plan_version, value.task_id, value.attempt),
        )
        tools = sorted(
            (
                copy.deepcopy(value)
                for value in self._tools.values()
                if value.run_id == run_id and value.tenant_id == tenant_id
            ),
            key=lambda value: (value.created_at, str(value.invocation_id)),
        )
        artifacts = sorted(
            (
                copy.deepcopy(value)
                for value in self._artifacts._artifacts.values()
                if value.run_id == run_id and value.tenant_id == tenant_id
            ),
            key=lambda value: (value.created_at, str(value.artifact_id)),
        )
        return {
            "run_id": str(run_id),
            "tenant_id": tenant_id,
            "contract": self._json(run.contract),
            "run_snapshot": {
                "status": run.status.value,
                "current_plan_version": run.current_plan_version,
                "request_hash": run.request_hash,
                "workflow_id": run.workflow_id,
                "version": run.version,
                "created_at": run.created_at.isoformat(),
                "updated_at": run.updated_at.isoformat(),
            },
            "plans": [
                {
                    "plan_id": str(value.plan_id),
                    "plan_version": value.plan_version,
                    "schema_version": value.schema_version,
                    "plan": self._json(value.plan_json),
                    "plan_hash": value.plan_hash,
                    "planner_model": value.planner_model,
                    "prompt_id": value.prompt_id,
                    "prompt_version": value.prompt_version,
                    "validation_status": value.validation_status,
                    "created_at": value.created_at.isoformat(),
                }
                for value in plans
            ],
            "task_executions": [
                {
                    "task_execution_id": str(value.task_execution_id),
                    "plan_version": value.plan_version,
                    "task_id": value.task_id,
                    "task_kind": value.task_kind,
                    "attempt": value.attempt,
                    "status": value.status,
                    "model_name": value.model_name,
                    "model_settings": self._json(value.model_settings),
                    "prompt_id": value.prompt_id,
                    "prompt_version": value.prompt_version,
                    "input_refs": self._json(value.input_refs),
                    "output": self._json(value.output_json),
                    "output_artifact_id": (
                        str(value.output_artifact_id) if value.output_artifact_id else None
                    ),
                    "error_code": value.error_code,
                    "usage": self._json(value.usage_json),
                    "started_at": value.started_at.isoformat() if value.started_at else None,
                    "completed_at": (
                        value.completed_at.isoformat() if value.completed_at else None
                    ),
                }
                for value in tasks
            ],
            "tool_invocations": [
                {
                    "invocation_id": str(value.invocation_id),
                    "plan_version": value.plan_version,
                    "task_id": value.task_id,
                    "tool_name": value.tool_name,
                    "tool_version": value.tool_version,
                    "effect": value.effect.value,
                    "args_hash": value.args_hash,
                    "args_redacted": self._json(value.args_redacted),
                    "data_scope_hash": value.data_scope_hash,
                    "policy_decision_id": value.policy_decision_id,
                    "policy_version": value.policy_version,
                    "status": value.status,
                    "result_hash": value.result_hash,
                    "result_artifact_id": (
                        str(value.result_artifact_id) if value.result_artifact_id else None
                    ),
                    "error_code": value.error_code,
                    "latency_ms": value.latency_ms,
                    "provider_request_id": value.provider_request_id,
                    "created_at": value.created_at.isoformat(),
                    "completed_at": (
                        value.completed_at.isoformat() if value.completed_at else None
                    ),
                }
                for value in tools
            ],
            "actions": [
                {
                    "action_id": str(action.action_id),
                    "action_type": action.action_type,
                    "tool_name": action.tool_name,
                    "tool_version": action.tool_version,
                    "payload_hash": action.payload_hash,
                    "preview": self._json(action.preview),
                    "risk": action.risk.value,
                    "approval_policy": action.approval_policy,
                    "required_approvals": action.required_approvals,
                    "status": action.status.value,
                    "idempotency_key": action.idempotency_key,
                    "policy_version": action.policy_version,
                    "receipt": self._json(action.receipt),
                    "receipt_artifact_id": self._receipt_artifact_id(action.receipt),
                    "verification": self._json(action.verification),
                    "failure_code": action.failure_code,
                    "approvals": self._json(action.approvals),
                    "created_at": action.created_at.isoformat(),
                    "updated_at": action.updated_at.isoformat(),
                }
                for action in actions
            ],
            "artifacts": [
                {
                    "artifact_id": str(artifact.artifact_id),
                    "task_id": None,
                    "kind": artifact.kind,
                    "uri": None,
                    "media_type": artifact.media_type,
                    "size_bytes": len(artifact.content),
                    "sha256": artifact.sha256,
                    "classification": artifact.classification.value,
                    "source": {
                        "scan_status": artifact.scan_status,
                        "scan_provenance": self._json(artifact.scan_provenance),
                    },
                    "created_by": artifact.created_by,
                    "retention_policy": ("expires_at" if artifact.expires_at else "default"),
                    "expires_at": (
                        artifact.expires_at.isoformat() if artifact.expires_at else None
                    ),
                    "deleted_at": (
                        artifact.deleted_at.isoformat() if artifact.deleted_at else None
                    ),
                    "created_at": artifact.created_at.isoformat(),
                }
                for artifact in artifacts
            ],
            "events": [
                {
                    "sequence_no": event.sequence_no,
                    "event_type": event.event_type,
                    "schema_version": event.schema_version,
                    "actor_type": event.actor_type,
                    "actor_id": event.actor_id,
                    "task_id": event.task_id,
                    "action_id": str(event.action_id) if event.action_id else None,
                    "payload": self._json(event.payload),
                    "payload_hash": event.payload_hash,
                    "correlation_id": event.correlation_id,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ],
        }

    @staticmethod
    def _receipt_artifact_id(receipt: Any) -> str | None:
        if not isinstance(receipt, Mapping):
            return None
        value = receipt.get("raw_receipt_artifact_id") or receipt.get("receipt_artifact_id")
        if value is None:
            return None
        try:
            return str(UUID(str(value)))
        except ValueError:
            raise ValueError("ACTION_RECEIPT_ARTIFACT_ID_INVALID") from None

    @staticmethod
    def _json(value: Any) -> Any:
        if value is None:
            return None
        return json.loads(canonical_json(value))


class InMemoryPlatformStore:
    def __init__(self) -> None:
        self.runs = InMemoryRunRepository()
        self.audit = InMemoryAuditRepository(self.runs)
        self.actions = InMemoryActionRepository(self.runs, self.audit)
        self.artifacts = InMemoryArtifactStore()
        self.audit.bind(self.actions, self.artifacts)
        self.capabilities = InMemoryCapabilityStore()
