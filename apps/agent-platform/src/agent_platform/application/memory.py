"""Application-level contracts for governed long-term memory reads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Protocol
from uuid import UUID

from agent_platform.domain.models import DataScope


@dataclass(frozen=True, slots=True)
class MemoryView:
    memory_id: UUID
    tenant_id: str
    subject_type: str
    subject_id: str
    memory_type: str
    content: str
    content_hash: str
    classification: str
    owner_id: str
    write_policy: str
    confidence: Decimal | None
    source_refs: tuple[str, ...]
    purpose: str
    data_scope: DataScope
    version: int
    valid_from: datetime
    valid_until: datetime | None


class MemoryContextReader(Protocol):
    async def list_for_context(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        data_scope: DataScope,
        purpose: str,
        now: datetime | None = None,
    ) -> tuple[MemoryView, ...]: ...
