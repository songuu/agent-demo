from __future__ import annotations

from pathlib import Path

from agent_platform.infrastructure.persistence.capacity_models import (
    CostLedgerEntry,
    RunCapacityReservation,
)
from agent_platform.infrastructure.persistence.capacity_repository import (
    PostgresCapacityCostRepository,
)

PLATFORM_ROOT = Path(__file__).resolve().parents[3]


def test_capacity_and_cost_tables_enforce_immutable_tenant_bound_contract() -> None:
    reservation = RunCapacityReservation.__table__
    ledger = CostLedgerEntry.__table__

    assert set(reservation.primary_key.columns.keys()) == {"tenant_id", "reservation_key"}
    assert {
        "requested_cost_usd",
        "daily_period",
        "monthly_period",
        "expires_at",
        "status",
        "run_id",
    } <= set(reservation.columns.keys())
    assert set(ledger.primary_key.columns.keys()) == {"tenant_id", "event_id"}
    assert {
        "run_id",
        "component",
        "amount_usd",
        "rate_catalog_id",
        "source_units",
        "occurred_at",
    } <= set(ledger.columns.keys())
    assert PostgresCapacityCostRepository.COST_COMPONENTS == {
        "model",
        "tool",
        "sandbox",
        "artifact",
        "workflow",
        "observability",
    }


def test_capacity_cost_migration_enables_rls_and_append_only_ledger() -> None:
    migration = (
        PLATFORM_ROOT / "migrations" / "versions" / "20260727_0009_capacity_cost_governance.py"
    ).read_text(encoding="utf-8")

    for table in ("run_capacity_reservations", "cost_ledger_entries"):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in migration
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in migration
        assert f"tenant_isolation_{table}" in migration
    assert "reject_cost_ledger_mutation" in migration
    assert "BEFORE UPDATE OR DELETE ON cost_ledger_entries" in migration
    assert "pg_advisory_xact_lock" not in migration
