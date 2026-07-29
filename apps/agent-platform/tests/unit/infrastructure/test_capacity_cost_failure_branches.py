from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import RunRecord
from agent_platform.infrastructure.capacity_cost import (
    AdmissionDecision,
    AuditCostReconciler,
    BudgetControlLevel,
    CapacityControlConfig,
    CapacityCostController,
    CostRateCatalog,
    RedisSharedReliability,
    RunPriority,
    SharedReliabilityConfig,
    TemporalQueueBacklogProbe,
)


class _Redis:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)

    async def eval(
        self,
        script: str,
        numkeys: int,
        *keys_and_args: object,
    ) -> object:
        del script, numkeys, keys_and_args
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Repository:
    def __init__(self) -> None:
        self.bindings: list[dict[str, object]] = []
        self.releases: list[dict[str, object]] = []

    async def find_reservation(self, tenant_id: str, key: str) -> None:
        del tenant_id, key
        return None

    async def reserve(self, **values: object) -> AdmissionDecision:
        del values
        return AdmissionDecision(
            newly_reserved=True,
            active_runs=1,
            budget_control_level=BudgetControlLevel.NORMAL,
            daily_utilization=Decimal("0.1"),
            monthly_utilization=Decimal("0.1"),
        )

    async def bind_run(self, **values: object) -> None:
        self.bindings.append(values)

    async def release(self, **values: object) -> None:
        self.releases.append(values)

    async def settle(self, **values: object) -> object:
        raise AssertionError(values)


class _Audit:
    def __init__(self, document: dict[str, Any]) -> None:
        self.document = document

    async def export_run(self, run_id: object, tenant_id: str) -> dict[str, Any]:
        del run_id, tenant_id
        return self.document


def _catalog() -> CostRateCatalog:
    return CostRateCatalog.model_validate(
        {
            "schema_version": "1.0",
            "catalog_id": "rates-v1",
            "currency": "USD",
            "effective_at": "2026-07-01T00:00:00Z",
            "rates": {
                "tool_call_usd": "0",
                "sandbox_cpu_second_usd": "0",
                "sandbox_memory_gib_second_usd": "0",
                "artifact_storage_gib_month_usd": "0",
                "artifact_transfer_gib_usd": "0",
                "workflow_second_usd": "0",
                "observability_event_usd": "0",
            },
            "default_artifact_retention_days": 90,
        }
    )


def _run(*, aware: bool = True) -> RunRecord:
    created = datetime(2026, 7, 27, tzinfo=UTC if aware else None)
    return RunRecord(
        run_id=uuid4(),
        tenant_id="tenant-a",
        principal_id="user-1",
        contract=type("Contract", (), {"max_cost_usd": Decimal("1")})(),
        idempotency_key="request-1",
        request_hash="a" * 64,
        workflow_id="workflow-1",
        created_at=created,
        updated_at=created,
    )


def test_strict_cost_catalog_digest_and_schema_fail_closed(tmp_path: Path) -> None:
    source = (
        Path(__file__).resolve().parents[3] / "deploy" / "catalogs" / "platform-cost-rates.v1.json"
    )
    digest = f"sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}"

    loaded = CostRateCatalog.from_path(source, expected_sha256=digest)
    assert loaded.catalog_id == "platform-cost-rates-2026-07"

    with pytest.raises(PlatformError) as mismatch:
        CostRateCatalog.from_path(source, expected_sha256="sha256:" + "0" * 64)
    assert mismatch.value.code == "COST_RATE_CATALOG_DIGEST_MISMATCH"

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}',
        encoding="utf-8",
    )
    with pytest.raises(PlatformError) as invalid:
        CostRateCatalog.from_path(duplicate)
    assert invalid.value.code == "COST_RATE_CATALOG_INVALID"

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 1_048_577)
    with pytest.raises(PlatformError) as too_large:
        CostRateCatalog.from_path(oversized)
    assert too_large.value.code == "COST_RATE_CATALOG_TOO_LARGE"

    with pytest.raises(ValueError, match="COST_RATE_CATALOG_ID_INVALID"):
        _catalog().model_copy(update={"catalog_id": ""}).__class__.model_validate(
            {**_catalog().model_dump(), "catalog_id": ""}
        )
    with pytest.raises(ValueError, match="COST_RATE_EFFECTIVE_AT_TIMEZONE_REQUIRED"):
        CostRateCatalog.model_validate(
            {**_catalog().model_dump(), "effective_at": "2026-07-01T00:00:00"}
        )


def test_capacity_and_shared_config_reject_invalid_thresholds() -> None:
    with pytest.raises(ValueError, match="CAPACITY_DAILY_BUDGET_EXCEEDS_MONTHLY"):
        CapacityControlConfig(
            tenant_daily_budget_usd=Decimal("2"),
            tenant_monthly_budget_usd=Decimal("1"),
        )
    with pytest.raises(
        ValueError,
        match="SHARED_CONTROL_HEARTBEAT_MUST_PRECEDE_LEASE_EXPIRY",
    ):
        SharedReliabilityConfig(lease_seconds=2, heartbeat_seconds=2)
    with pytest.raises(ValueError, match="SHARED_CONTROL_KEY_SECRET_TOO_SHORT"):
        RedisSharedReliability(_Redis([]), key_hmac_secret=b"short")
    with pytest.raises(ValueError, match="SHARED_CONTROL_NAMESPACE_INVALID"):
        RedisSharedReliability(
            _Redis([]),
            key_hmac_secret=b"k" * 32,
            namespace="",
        )
    with pytest.raises(ValueError, match="TEMPORAL_QUEUE_PROBE_SCOPE_REQUIRED"):
        TemporalQueueBacklogProbe(object(), namespace="", task_queue="runs")


@pytest.mark.asyncio
async def test_shared_provider_failure_and_half_open_nonfailure_update_circuit() -> None:
    failed = RedisSharedReliability(
        _Redis(
            [
                (1, 1, 0),
                (1, 0),
                (1,),  # record failure
                (1,),  # release
            ]
        ),
        key_hmac_secret=b"k" * 32,
    )

    async def provider_failure() -> str:
        raise TimeoutError("provider timed out")

    with pytest.raises(TimeoutError):
        await failed.call("tool:failure", provider_failure)

    half_open = RedisSharedReliability(
        _Redis(
            [
                (1, 1, 0),
                (2, 0),
                (1,),  # clear successful half-open probe
                (1,),  # release
            ]
        ),
        key_hmac_secret=b"k" * 32,
    )

    async def policy_denial() -> str:
        raise PlatformError("POLICY_DENIED", "denied", retryable=False)

    with pytest.raises(PlatformError, match="denied"):
        await half_open.call(
            "tool:probe",
            policy_denial,
            is_failure=lambda error: error.retryable if isinstance(error, PlatformError) else True,
        )


@pytest.mark.asyncio
async def test_shared_control_and_capacity_controller_validate_backend_contracts() -> None:
    invalid = RedisSharedReliability(
        _Redis([(1, 1, 0), (9, 0), (1,)]),
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError) as invalid_circuit:
        await invalid.call("model:invalid", _return_ok)
    assert invalid_circuit.value.code == "SHARED_CONTROL_RESPONSE_INVALID"

    with pytest.raises(ValueError, match="SHARED_CONTROL_SCOPE_INVALID"):
        invalid._scope_digest("")
    for value in (None, ("not-an-int",)):
        with pytest.raises(PlatformError, match="invalid response"):
            invalid._parse_integer_tuple(value, 1)

    repository = _Repository()
    controller = CapacityCostController(
        repository,
        queue_probe=None,
        key_hmac_secret=b"k" * 32,
    )
    with pytest.raises(PlatformError) as queue_required:
        await controller.admit_run(
            tenant_id="tenant-a",
            idempotency_key="request-1",
            requested_cost_usd=Decimal("1"),
            max_duration_seconds=10,
            priority=RunPriority.NORMAL,
        )
    assert queue_required.value.code == "CAPACITY_QUEUE_PROBE_REQUIRED"

    await controller.bind_run(
        tenant_id="tenant-a",
        idempotency_key="request-1",
        run_id=uuid4(),
    )
    await controller.release_if_unbound(
        tenant_id="tenant-a",
        idempotency_key="request-1",
    )
    assert len(repository.bindings) == 1
    assert repository.releases[0]["only_if_unbound"] is True

    with pytest.raises(PlatformError) as reconciler_required:
        await controller.settle_run(_run())
    assert reconciler_required.value.code == "COST_RECONCILER_REQUIRED"
    with pytest.raises(ValueError, match="CAPACITY_RESERVATION_IDENTITY_INVALID"):
        controller._reservation_key("", "request-1")
    with pytest.raises(ValueError, match="CAPACITY_CONTROL_KEY_SECRET_TOO_SHORT"):
        CapacityCostController(
            repository,
            queue_probe=None,
            key_hmac_secret=b"short",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("document", "expected_code"),
    [
        (
            {
                "task_executions": {},
                "tool_invocations": [],
                "artifacts": [],
                "events": [],
            },
            "COST_AUDIT_EXPORT_INVALID",
        ),
        (
            {
                "task_executions": [
                    {
                        "task_id": "sandbox-1",
                        "task_kind": "sandbox",
                        "usage": {
                            "sandbox_cpu_seconds": -1,
                            "sandbox_memory_gib_seconds": 1,
                        },
                    }
                ],
                "tool_invocations": [],
                "artifacts": [],
                "events": [],
            },
            "COST_USAGE_INCOMPLETE",
        ),
        (
            {
                "task_executions": [],
                "tool_invocations": [],
                "artifacts": [{"size_bytes": "NaN", "deleted_at": None}],
                "events": [],
            },
            "COST_USAGE_INVALID",
        ),
        (
            {
                "task_executions": [],
                "tool_invocations": [],
                "artifacts": [
                    {
                        "size_bytes": 1,
                        "created_at": "not-a-time",
                        "expires_at": "also-not-a-time",
                        "deleted_at": None,
                    }
                ],
                "events": [],
            },
            "COST_USAGE_INVALID",
        ),
    ],
)
async def test_cost_reconciliation_rejects_incomplete_audit_evidence(
    document: dict[str, Any],
    expected_code: str,
) -> None:
    with pytest.raises(PlatformError) as caught:
        await AuditCostReconciler(_Audit(document), _catalog()).reconcile(_run())
    assert caught.value.code == expected_code


@pytest.mark.asyncio
async def test_cost_reconciliation_rejects_naive_run_timestamps() -> None:
    document = {
        "task_executions": [],
        "tool_invocations": [],
        "artifacts": [],
        "events": [],
    }
    with pytest.raises(PlatformError) as caught:
        await AuditCostReconciler(_Audit(document), _catalog()).reconcile(_run(aware=False))
    assert caught.value.code == "COST_TIMESTAMP_INVALID"


async def _return_ok() -> str:
    return "ok"
