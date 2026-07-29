"""Retention sweep primitives that preserve immutable audit evidence."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

type RetentionHandler = Callable[["RetentionCandidate"], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class RetentionCandidate:
    tenant_id: str
    resource_type: str
    resource_id: str
    expires_at: datetime
    immutable_audit: bool = False


@dataclass(frozen=True, slots=True)
class RetentionReport:
    scanned: int
    deleted: int
    archived: int
    retained: int


class RetentionService:
    def __init__(
        self,
        *,
        delete: RetentionHandler,
        archive: RetentionHandler,
    ) -> None:
        self._delete = delete
        self._archive = archive

    async def sweep(
        self,
        candidates: Iterable[RetentionCandidate],
        *,
        now: datetime | None = None,
    ) -> RetentionReport:
        current = now or datetime.now(UTC)
        scanned = deleted = archived = retained = 0
        for candidate in candidates:
            scanned += 1
            if candidate.expires_at > current:
                retained += 1
                continue
            if candidate.immutable_audit:
                await self._archive(candidate)
                archived += 1
            else:
                await self._delete(candidate)
                deleted += 1
        return RetentionReport(
            scanned=scanned,
            deleted=deleted,
            archived=archived,
            retained=retained,
        )


def main() -> None:
    """Delegate the compatibility entry point to the production worker."""

    from agent_platform.infrastructure.retention_worker import main as worker_main

    worker_main()
