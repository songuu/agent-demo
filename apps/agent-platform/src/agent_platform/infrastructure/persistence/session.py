"""Async database session construction with transaction-scoped tenant isolation."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

type AsyncSessionFactory = async_sessionmaker[AsyncSession]


def create_session_factory(
    database_url: str,
    *,
    pool_size: int = 10,
    max_overflow: int = 20,
) -> AsyncSessionFactory:
    """Create a PostgreSQL session factory whose pool always rolls back on return."""
    engine = create_async_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_reset_on_return="rollback",
    )
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def dispose_session_factory(factory: AsyncSessionFactory) -> None:
    bind = factory.kw.get("bind")
    if isinstance(bind, AsyncEngine):
        await bind.dispose()


@asynccontextmanager
async def tenant_session(
    factory: AsyncSessionFactory,
    tenant_id: str,
) -> AsyncIterator[AsyncSession]:
    """Open one transaction and install an RLS tenant derived from the Principal.

    `set_config(..., true)` is transaction local. The unconditional rollback in
    `finally` is intentional: it also clears the setting if user code exits before
    committing, preventing tenant bleed when the pooled connection is reused.
    """
    if not tenant_id or "\x00" in tenant_id:
        raise ValueError("tenant_id must be a non-empty verified identifier")

    session = factory()
    try:
        await session.begin()
        await session.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )
        yield session
    finally:
        if session.in_transaction():
            await session.rollback()
        await session.close()
