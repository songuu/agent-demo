from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_platform.infrastructure.persistence import session as session_module
from agent_platform.infrastructure.persistence.session import (
    create_session_factory,
    dispose_session_factory,
    tenant_session,
)
from agent_platform.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork


class _Session:
    def __init__(self, *, in_transaction: bool) -> None:
        self._in_transaction = in_transaction
        self.begin = AsyncMock()
        self.execute = AsyncMock()
        self.rollback = AsyncMock()
        self.close = AsyncMock()

    def in_transaction(self) -> bool:
        return self._in_transaction


def test_create_session_factory_pins_safe_pool_and_session_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = object()
    factory = object()
    create_engine = MagicMock(return_value=engine)
    make_session = MagicMock(return_value=factory)
    monkeypatch.setattr(session_module, "create_async_engine", create_engine)
    monkeypatch.setattr(session_module, "async_sessionmaker", make_session)

    created = create_session_factory(
        "postgresql+asyncpg://localhost/platform",
        pool_size=4,
        max_overflow=6,
    )

    assert created is factory
    create_engine.assert_called_once_with(
        "postgresql+asyncpg://localhost/platform",
        pool_pre_ping=True,
        pool_size=4,
        max_overflow=6,
        pool_reset_on_return="rollback",
    )
    make_session.assert_called_once_with(
        engine,
        expire_on_commit=False,
        autoflush=False,
    )


@pytest.mark.asyncio
async def test_dispose_session_factory_closes_only_async_engine_bind() -> None:
    engine = MagicMock(spec=AsyncEngine)
    engine.dispose = AsyncMock()
    await dispose_session_factory(cast(Any, SimpleNamespace(kw={"bind": engine})))
    engine.dispose.assert_awaited_once()

    await dispose_session_factory(
        cast(Any, SimpleNamespace(kw={"bind": object()})),
    )


@pytest.mark.asyncio
async def test_tenant_session_skips_redundant_rollback_after_caller_commit() -> None:
    session = _Session(in_transaction=False)
    async with tenant_session(cast(Any, lambda: session), "tenant-a"):
        pass
    session.rollback.assert_not_awaited()
    session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_unit_of_work_exit_is_idempotent_and_rolls_back_uncommitted_work() -> None:
    session = _Session(in_transaction=True)
    unit = SqlAlchemyUnitOfWork(cast(Any, lambda: session), "tenant-a")
    await unit.__aexit__(None, None, None)

    await unit.__aenter__()
    await unit.__aexit__(None, None, None)

    session.rollback.assert_awaited_once()
    session.close.assert_awaited_once()
    assert unit.session is None
