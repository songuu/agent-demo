"""SQLAlchemy Unit of Work used by application ports."""

from __future__ import annotations

from types import TracebackType

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.infrastructure.persistence.repositories import (
    ActionRepository,
    IdempotencyRepository,
    RunRepository,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory


class SqlAlchemyUnitOfWork:
    """Own exactly one tenant-scoped transaction.

    Repositories never commit independently, so snapshot/event/outbox writes and
    action locks remain atomic. Application services explicitly call `commit`.
    """

    def __init__(self, factory: AsyncSessionFactory, tenant_id: str) -> None:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        self._factory = factory
        self.tenant_id = tenant_id
        self.session: AsyncSession | None = None
        self.runs: RunRepository
        self.actions: ActionRepository
        self.idempotency: IdempotencyRepository

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self.session = self._factory()
        await self.session.begin()
        await self.session.execute(
            text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )
        self.runs = RunRepository(self.session)
        self.actions = ActionRepository(self.session)
        self.idempotency = IdempotencyRepository(self.session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.session is None:
            return
        # A caller that forgot to commit must never accidentally persist changes.
        if self.session.in_transaction():
            await self.session.rollback()
        await self.session.close()
        self.session = None

    async def commit(self) -> None:
        if self.session is None:
            raise RuntimeError("unit of work has not been entered")
        await self.session.commit()

    async def rollback(self) -> None:
        if self.session is None:
            raise RuntimeError("unit of work has not been entered")
        await self.session.rollback()
