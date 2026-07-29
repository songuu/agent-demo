"""Application WorkflowStarter adapter backed by Temporal."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import timedelta
from hashlib import sha256
from typing import Any
from uuid import UUID

from opentelemetry.trace import Tracer
from temporalio.client import Client
from temporalio.common import WorkflowIDConflictPolicy, WorkflowIDReusePolicy
from temporalio.contrib.opentelemetry import TracingInterceptor

from agent_platform.workflows.recovery_workflow import (
    ActionRecoveryWorkflow,
    StartActionRecoveryCommand,
)
from agent_platform.workflows.temporal_workflow import AgentRunWorkflow, StartRunCommand

type ActionWorkflowResolver = Callable[[UUID, str], Awaitable[str]]


class TemporalWorkflowStarter:
    """Route application lifecycle commands to stable Temporal workflow IDs."""

    def __init__(
        self,
        *,
        client: Client,
        task_queue: str,
        commit_task_queue: str = "agent-commits",
        action_workflow_resolver: ActionWorkflowResolver | None = None,
        default_max_replans: int = 2,
        default_run_timeout_seconds: int = 900,
        default_max_tool_calls: int = 100,
        approval_timeout_seconds: int = 86_400,
    ) -> None:
        if not task_queue or not commit_task_queue:
            raise ValueError("TEMPORAL_TASK_QUEUE_REQUIRED")
        self._client = client
        self._task_queue = task_queue
        self._commit_task_queue = commit_task_queue
        self._action_workflow_resolver = action_workflow_resolver
        self._default_max_replans = default_max_replans
        self._default_run_timeout_seconds = default_run_timeout_seconds
        self._default_max_tool_calls = default_max_tool_calls
        self._approval_timeout_seconds = approval_timeout_seconds

    @classmethod
    async def connect(
        cls,
        *,
        address: str,
        namespace: str,
        task_queue: str,
        commit_task_queue: str = "agent-commits",
        api_key: str | None = None,
        tls: bool | None = None,
        action_workflow_resolver: ActionWorkflowResolver | None = None,
        tracer: Tracer | None = None,
        **defaults: Any,
    ) -> TemporalWorkflowStarter:
        client = await Client.connect(
            address,
            namespace=namespace,
            api_key=api_key,
            tls=tls,
            interceptors=(TracingInterceptor(tracer),),
        )
        return cls(
            client=client,
            task_queue=task_queue,
            commit_task_queue=commit_task_queue,
            action_workflow_resolver=action_workflow_resolver,
            **defaults,
        )

    @property
    def client(self) -> Client:
        return self._client

    async def start(
        self,
        run_id: UUID,
        tenant_id: str,
        correlation_id: str,
        *,
        contract: Any | None = None,
    ) -> None:
        max_replans = (
            int(contract.max_replans) if contract is not None else self._default_max_replans
        )
        max_duration_seconds = (
            int(contract.max_duration_seconds)
            if contract is not None
            else self._default_run_timeout_seconds
        )
        max_tool_calls = (
            int(contract.max_tool_calls) if contract is not None else self._default_max_tool_calls
        )
        command = StartRunCommand(
            run_id=str(run_id),
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            max_replans=max_replans,
            max_duration_seconds=max_duration_seconds,
            max_tool_calls=max_tool_calls,
            approval_timeout_seconds=self._approval_timeout_seconds,
            commit_task_queue=self._commit_task_queue,
        )
        await self._client.start_workflow(
            AgentRunWorkflow.run,
            command,
            id=self.workflow_id(run_id),
            task_queue=self._task_queue,
            run_timeout=timedelta(
                seconds=(max_duration_seconds + self._approval_timeout_seconds + 300)
            ),
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            static_summary="Bounded Agent platform run",
        )

    async def start_action_recovery(
        self,
        *,
        run_id: UUID,
        action_id: UUID,
        tenant_id: str,
        correlation_id: str,
        requested_by: str,
        operation: str,
        reason: str | None = None,
    ) -> str:
        """Submit a secret-free recovery command to the commit task queue."""

        command = StartActionRecoveryCommand(
            run_id=str(run_id),
            action_id=str(action_id),
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            requested_by=requested_by,
            operation=operation,
            reason=reason,
        )
        correlation_digest = sha256(correlation_id.encode("utf-8")).hexdigest()[:16]
        workflow_id = f"action-recovery-{action_id}-{operation}-{correlation_digest}"
        await self._client.start_workflow(
            ActionRecoveryWorkflow.run,
            command,
            id=workflow_id,
            task_queue=self._commit_task_queue,
            run_timeout=timedelta(minutes=15),
            id_reuse_policy=WorkflowIDReusePolicy.REJECT_DUPLICATE,
            id_conflict_policy=WorkflowIDConflictPolicy.USE_EXISTING,
            static_summary="Action transaction recovery",
        )
        return workflow_id

    async def cancel(self, run_id: UUID, tenant_id: str, reason: str) -> None:
        del tenant_id
        await self._handle(run_id).signal(AgentRunWorkflow.cancel, reason)

    async def pause(self, run_id: UUID, tenant_id: str, reason: str) -> None:
        del tenant_id
        await self._handle(run_id).signal(AgentRunWorkflow.pause, reason)

    async def resume(self, run_id: UUID, tenant_id: str) -> None:
        del tenant_id
        await self._handle(run_id).signal(AgentRunWorkflow.resume)

    async def notify_action(
        self,
        action_id: UUID,
        tenant_id: str,
        decision: str,
    ) -> None:
        if self._action_workflow_resolver is None:
            raise RuntimeError("TEMPORAL_ACTION_WORKFLOW_RESOLVER_REQUIRED")
        workflow_id = await self._action_workflow_resolver(action_id, tenant_id)
        handle = self._client.get_workflow_handle(workflow_id)
        await handle.signal(
            AgentRunWorkflow.decide_action,
            args=[str(action_id), decision],
        )

    def _handle(self, run_id: UUID) -> Any:
        return self._client.get_workflow_handle(self.workflow_id(run_id))

    @staticmethod
    def workflow_id(run_id: UUID) -> str:
        return f"agent-run-{run_id}"
