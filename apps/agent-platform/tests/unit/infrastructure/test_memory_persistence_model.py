from __future__ import annotations

from agent_platform.infrastructure.persistence.models import MemoryRecord


def test_memory_record_persists_context_authorization_and_version_fields() -> None:
    columns = set(MemoryRecord.__table__.c.keys())

    assert {"purpose", "data_scope", "memory_version"} <= columns
