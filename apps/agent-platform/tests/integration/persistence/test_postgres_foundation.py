from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_foundation_migration_has_partition_rls_and_transition_function() -> None:
    database_url = os.getenv("AGENT_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AGENT_TEST_DATABASE_URL is required for PostgreSQL integration tests")

    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as connection:
            partition = await connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_partitioned_table p "
                    "JOIN pg_class c ON c.oid = p.partrelid "
                    "WHERE c.relname = 'run_events')"
                )
            )
            rls = await connection.scalar(
                text("SELECT relrowsecurity FROM pg_class WHERE relname = 'agent_runs'")
            )
            transition = await connection.scalar(
                text(
                    "SELECT to_regprocedure("
                    "'transition_run(uuid,text,run_status[],run_status,bigint,text,"
                    "text,text,text,jsonb,text)') IS NOT NULL"
                )
            )

        assert partition is True
        assert rls is True
        assert transition is True
    finally:
        await engine.dispose()
