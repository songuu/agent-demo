from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import RunRecord
from agent_platform.domain.enums import RunStatus
from agent_platform.infrastructure.capacity_cost import (
    AuditCostReconciler,
    CapacityControlConfig,
    CostComponent,
    CostRateCatalog,
    QueueBacklog,
    RedisSharedReliability,
    SharedReliabilityConfig,
    TemporalQueueBacklogProbe,
)


class _Redis:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, int, tuple[object, ...]]] = []

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> Any:
        self.calls.append((script, numkeys, keys_and_args))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.mark.asyncio
async def test_shared_reliability_uses_server_time_hashed_keys_and_releases_slot() -> None:
    redis = _Redis(
        [
            (1, 1, 0),  # slot acquired
            (1, 0),  # circuit closed
            (1,),  # circuit success
            (1,),  # slot release
        ]
    )
    control = RedisSharedReliability(
        redis,
        key_hmac_secret=b"k" * 32,
        config=SharedReliabilityConfig(
            max_in_flight=2,
            max_queued=3,
            queue_timeout_seconds=0.2,
            lease_seconds=5,
            heartbeat_seconds=2,
        ),
    )

    result = await control.call(
        "model:project-secret:gpt-5.6-sol",
        lambda: _return("ok"),
    )

    assert result == "ok"
    assert len(redis.calls) == 4
    scripts = [call[0] for call in redis.calls]
    assert all('redis.call("TIME")' in script for script in (scripts[0], scripts[1]))
    rendered_keys = " ".join(
        str(value) for _, numkeys, values in redis.calls for value in values[:numkeys]
    )
    assert "project-secret" not in rendered_keys
    assert "{shared-control-v1}" in rendered_keys


@pytest.mark.asyncio
async def test_shared_reliability_fails_closed_when_backend_or_queue_is_unavailable() -> None:
    unavailable = RedisSharedReliability(
        _Redis([OSError("redis down")]),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError) as failed:
        await unavailable.call("tool:crm.read", lambda: _return("never"))
    assert failed.value.code == "SHARED_CONTROL_BACKEND_UNAVAILABLE"
    assert failed.value.retryable is True

    rejected = RedisSharedReliability(
        _Redis([(-1, 8, 100)]),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError) as full:
        await rejected.call("tool:crm.read", lambda: _return("never"))
    assert full.value.code == "BACKPRESSURE_REJECTED"


@pytest.mark.asyncio
async def test_shared_circuit_opens_across_replicas_and_does_not_call_provider() -> None:
    redis = _Redis(
        [
            (1, 1, 0),  # slot acquired
            (0, 12),  # circuit open with retry-after
            (1,),  # slot release
        ]
    )
    control = RedisSharedReliability(redis, key_hmac_secret=b"k" * 32)
    called = False

    async def provider() -> str:
        nonlocal called
        called = True
        return "unexpected"

    with pytest.raises(PlatformError) as caught:
        await control.call("model:project:gpt-5.6-sol", provider)

    assert caught.value.code == "CIRCUIT_OPEN"
    assert caught.value.context["retry_after_seconds"] == 12
    assert called is False


class _WorkflowService:
    def __init__(self, replies: list[object]) -> None:
        self.replies = list(replies)
        self.requests: list[object] = []

    async def describe_task_queue(self, request: object) -> object:
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _queue_response(backlog: int, age_seconds: float) -> object:
    return SimpleNamespace(
        stats=SimpleNamespace(
            approximate_backlog_count=backlog,
            approximate_backlog_age=SimpleNamespace(
                ToTimedelta=lambda: timedelta(seconds=age_seconds)
            ),
        )
    )


@pytest.mark.asyncio
async def test_temporal_queue_probe_uses_real_workflow_and_activity_queue_stats() -> None:
    service = _WorkflowService([_queue_response(4, 2), _queue_response(9, 7)])
    client = SimpleNamespace(workflow_service=service)
    probe = TemporalQueueBacklogProbe(
        client,
        namespace="agent-platform-prod",
        task_queue="agent-runs",
    )

    state = await probe.snapshot()

    assert state == QueueBacklog(backlog=13, oldest_age_seconds=7)
    assert len(service.requests) == 2


@pytest.mark.asyncio
async def test_temporal_queue_probe_failure_is_fail_closed() -> None:
    client = SimpleNamespace(
        workflow_service=_WorkflowService([TimeoutError("temporal unavailable")])
    )
    probe = TemporalQueueBacklogProbe(client, namespace="prod", task_queue="agent-runs")

    with pytest.raises(PlatformError) as caught:
        await probe.snapshot()

    assert caught.value.code == "CAPACITY_QUEUE_PROBE_UNAVAILABLE"
    assert caught.value.http_status == 503


def _rate_catalog() -> CostRateCatalog:
    return CostRateCatalog.model_validate(
        {
            "schema_version": "1.0",
            "catalog_id": "platform-cost-rates-2026-07",
            "currency": "USD",
            "effective_at": "2026-07-01T00:00:00Z",
            "rates": {
                "tool_call_usd": "0.01",
                "sandbox_cpu_second_usd": "0.001",
                "sandbox_memory_gib_second_usd": "0.002",
                "artifact_storage_gib_month_usd": "0.03",
                "artifact_transfer_gib_usd": "0.04",
                "workflow_second_usd": "0.0001",
                "observability_event_usd": "0.0002",
            },
            "default_artifact_retention_days": 90,
        }
    )


class _Audit:
    def __init__(self, export: dict[str, Any]) -> None:
        self.export = export

    async def export_run(self, run_id: object, tenant_id: str) -> dict[str, Any]:
        return self.export


@pytest.mark.asyncio
async def test_cost_reconciliation_covers_every_architecture_component() -> None:
    started = datetime(2026, 7, 27, 1, 0, tzinfo=UTC)
    completed = started + timedelta(seconds=10)
    run = RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=SimpleNamespace(max_cost_usd=Decimal("10")),
        idempotency_key="request-1",
        request_hash="a" * 64,
        workflow_id="workflow-1",
        status=RunStatus.COMPLETED,
        cost_actual_usd=Decimal("1.25"),
        created_at=started,
        updated_at=completed,
        completed_at=completed,
    )
    export = {
        "task_executions": [
            {
                "task_kind": "sandbox",
                "usage": {
                    "sandbox_cpu_seconds": 20,
                    "sandbox_memory_gib_seconds": 10,
                },
            }
        ],
        "tool_invocations": [{"invocation_id": "1"}, {"invocation_id": "2"}],
        "artifacts": [
            {
                "size_bytes": 1024**3,
                "created_at": started.isoformat(),
                "expires_at": (started + timedelta(days=90)).isoformat(),
                "deleted_at": None,
            }
        ],
        "events": [{"sequence_no": index} for index in range(5)],
    }
    reconciler = AuditCostReconciler(
        _Audit(export),
        _rate_catalog(),
    )

    result = await reconciler.reconcile(run)

    assert set(result.components) == set(CostComponent)
    assert result.components[CostComponent.MODEL] == Decimal("1.250000")
    assert result.components[CostComponent.TOOL] == Decimal("0.020000")
    assert result.components[CostComponent.SANDBOX] == Decimal("0.040000")
    assert result.components[CostComponent.ARTIFACT] == Decimal("0.130000")
    assert result.components[CostComponent.WORKFLOW] == Decimal("0.001000")
    assert result.components[CostComponent.OBSERVABILITY] == Decimal("0.001000")
    assert result.total_usd == Decimal("1.442000")
    assert result.rate_catalog_id == "platform-cost-rates-2026-07"
    assert result.source_counts == {
        "artifacts": 1,
        "events": 5,
        "sandbox_tasks": 1,
        "tool_invocations": 2,
    }


@pytest.mark.asyncio
async def test_sandbox_cost_fails_closed_without_measured_resource_usage() -> None:
    run = RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=SimpleNamespace(max_cost_usd=Decimal("10")),
        idempotency_key="request-1",
        request_hash="a" * 64,
        workflow_id="workflow-1",
    )
    reconciler = AuditCostReconciler(
        _Audit(
            {
                "task_executions": [{"task_kind": "sandbox", "usage": {}}],
                "tool_invocations": [],
                "artifacts": [],
                "events": [],
            }
        ),
        _rate_catalog(),
    )

    with pytest.raises(PlatformError) as caught:
        await reconciler.reconcile(run)

    assert caught.value.code == "COST_USAGE_INCOMPLETE"


def test_capacity_thresholds_are_bounded_and_ordered() -> None:
    config = CapacityControlConfig()
    assert config.midpoint_ratio < config.restrict_ratio < config.critical_only_ratio

    with pytest.raises(ValueError, match="CAPACITY_BUDGET_THRESHOLDS_INVALID"):
        CapacityControlConfig(
            midpoint_ratio=Decimal("0.90"),
            restrict_ratio=Decimal("0.80"),
        )


async def _return(value: str) -> str:
    return value
