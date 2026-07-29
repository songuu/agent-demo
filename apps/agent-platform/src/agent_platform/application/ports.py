"""Ports keep model code independent from databases and external SDKs."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol
from uuid import UUID

from agent_platform.application.records import (
    ActionAuditTransaction,
    ActionRecord,
    ArtifactRecord,
    AuditEvent,
    EventRecord,
    PlanExecutionRecord,
    RunRecord,
    TaskExecutionRecord,
    ToolInvocationRecord,
)


class RunRepository(Protocol):
    async def create_once(self, run: RunRecord) -> tuple[RunRecord, bool]: ...
    async def get(self, run_id: UUID, tenant_id: str) -> RunRecord: ...
    async def save(self, run: RunRecord, expected_version: int) -> RunRecord: ...
    async def append_event(
        self,
        run: RunRecord,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_id: str,
    ) -> EventRecord: ...
    async def events_after(
        self, run_id: UUID, tenant_id: str, sequence_no: int
    ) -> Sequence[EventRecord]: ...
    def trajectory_transaction(
        self, run_id: UUID, tenant_id: str
    ) -> AbstractAsyncContextManager[Any]: ...


class ActionRepository(Protocol):
    async def create_once(self, action: ActionRecord) -> tuple[ActionRecord, bool]: ...
    async def create_once_with_event(
        self,
        action: ActionRecord,
        event: AuditEvent,
        invocation: ToolInvocationRecord | None = None,
    ) -> tuple[ActionRecord, bool, EventRecord | None]: ...
    async def get(self, action_id: UUID, tenant_id: str) -> ActionRecord: ...
    async def get_for_update(
        self, action_id: UUID, tenant_id: str
    ) -> AbstractAsyncContextManager[ActionRecord]: ...
    async def transaction(
        self, action_id: UUID, tenant_id: str
    ) -> AbstractAsyncContextManager[ActionAuditTransaction]: ...
    async def list_for_run(self, run_id: UUID, tenant_id: str) -> Sequence[ActionRecord]: ...
    async def save(self, action: ActionRecord, expected_version: int) -> ActionRecord: ...


class AuditRepository(Protocol):
    async def save_plan_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        plan: PlanExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]: ...
    async def start_task(
        self, execution: TaskExecutionRecord, event: AuditEvent
    ) -> EventRecord | None: ...
    async def complete_task_with_run(
        self,
        run: RunRecord,
        expected_version: int,
        execution: TaskExecutionRecord,
        event: AuditEvent,
    ) -> tuple[RunRecord, EventRecord]: ...
    async def finish_task(
        self, execution: TaskExecutionRecord, event: AuditEvent
    ) -> EventRecord: ...
    async def record_tool(
        self, invocation: ToolInvocationRecord, event: AuditEvent
    ) -> EventRecord: ...
    async def export_run(self, run_id: UUID, tenant_id: str) -> Mapping[str, Any]: ...


class ArtifactStore(Protocol):
    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord: ...
    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord: ...
    async def delete(self, artifact_id: UUID, tenant_id: str) -> None: ...


class ToolAdapter(Protocol):
    async def read(self, args: Mapping[str, Any], credential: Any) -> Any: ...
    async def preview(self, args: Mapping[str, Any], credential: Any) -> Mapping[str, Any]: ...
    async def lookup_by_idempotency_key(
        self, idempotency_key: str, credential: Any
    ) -> Any | None: ...
    async def commit(
        self, payload: Mapping[str, Any], credential: Any, idempotency_key: str
    ) -> Any: ...
    async def verify(self, action: ActionRecord, receipt: Any, credential: Any) -> Any: ...
    async def compensate(self, action: ActionRecord, receipt: Any, credential: Any) -> Any: ...


class CredentialBroker(Protocol):
    async def issue(
        self,
        tenant_id: str,
        principal_id: str,
        scopes: frozenset[str],
        ttl_seconds: int,
    ) -> Any: ...


class PolicyEngine(Protocol):
    async def authorize_tool(self, request: Mapping[str, Any]) -> Any: ...
    async def authorize_action(self, request: Mapping[str, Any]) -> Any: ...


class WorkflowStarter(Protocol):
    async def start(
        self,
        run_id: UUID,
        tenant_id: str,
        correlation_id: str,
        *,
        contract: Any | None = None,
    ) -> None: ...
    async def cancel(self, run_id: UUID, tenant_id: str, reason: str) -> None: ...
    async def pause(self, run_id: UUID, tenant_id: str, reason: str) -> None: ...
    async def resume(self, run_id: UUID, tenant_id: str) -> None: ...
    async def notify_action(
        self,
        action_id: UUID,
        tenant_id: str,
        decision: str,
    ) -> None: ...


class AgentRuntimePort(Protocol):
    def audit_metadata(
        self,
        role: str,
        contract: Any,
        *,
        task: Any | None = None,
        retry_count: int = 0,
    ) -> Mapping[str, Any]: ...
    async def plan(self, context: Any, contract: Any) -> Any: ...
    async def execute_task(
        self, context: Any, task: Any, dependencies: Mapping[str, Any]
    ) -> Any: ...
    async def verify(
        self, context: Any, contract: Any, plan: Any, outputs: Mapping[str, Any]
    ) -> Any: ...


class ContentScanner(Protocol):
    async def scan(self, chunks: AsyncIterator[bytes], *, media_type: str) -> str: ...
