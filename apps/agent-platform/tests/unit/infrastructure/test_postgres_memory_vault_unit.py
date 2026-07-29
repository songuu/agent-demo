from __future__ import annotations

import copy
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, cast
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope
from agent_platform.infrastructure.memory_vault import EncryptedMemoryRecord
from agent_platform.infrastructure.persistence import postgres_memory_vault
from agent_platform.infrastructure.persistence.models import (
    MemoryLifecycleEvent as DatabaseMemoryLifecycleEvent,
)
from agent_platform.infrastructure.persistence.postgres_memory_vault import (
    AesGcmMemoryContentCipher,
    PostgresMemoryVault,
)


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    def __init__(
        self,
        *,
        scalar_results: list[Any] | None = None,
        scalars_results: list[list[Any]] | None = None,
    ) -> None:
        self.scalar_results = deque(scalar_results or [])
        self.scalars_results = deque(scalars_results or [])
        self.added: list[Any] = []
        self.added_many: list[Any] = []
        self.flushes = 0
        self.commits = 0

    async def scalar(self, _statement: Any) -> Any:
        if not self.scalar_results:
            raise AssertionError("unexpected scalar query")
        return self.scalar_results.popleft()

    async def scalars(self, _statement: Any) -> _Rows:
        if not self.scalars_results:
            raise AssertionError("unexpected scalars query")
        return _Rows(self.scalars_results.popleft())

    def add(self, value: Any) -> None:
        self.added.append(value)

    def add_all(self, values: list[Any]) -> None:
        self.added_many.extend(values)

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1


def _patch_session(monkeypatch: pytest.MonkeyPatch, session: _Session) -> None:
    @asynccontextmanager
    async def fake_tenant_session(
        _factory: Any,
        tenant_id: str,
    ) -> AsyncIterator[_Session]:
        assert tenant_id == "tenant-a"
        yield session

    monkeypatch.setattr(
        postgres_memory_vault,
        "tenant_session",
        fake_tenant_session,
    )


def _scope(
    *,
    tenant_id: str = "tenant-a",
    resource_ids: frozenset[str] = frozenset(),
    row_filter: dict[str, Any] | None = None,
    allowed_fields: frozenset[str] = frozenset(),
    classifications: frozenset[DataClassification] = frozenset({DataClassification.INTERNAL}),
) -> DataScope:
    return DataScope(
        tenant_id=tenant_id,
        resource_types=frozenset({"memory"}),
        resource_ids=resource_ids,
        row_filter=row_filter or {},
        allowed_fields=allowed_fields,
        classifications=classifications,
    )


def _vault() -> PostgresMemoryVault:
    return PostgresMemoryVault(
        cast(Any, object()),
        cipher=AesGcmMemoryContentCipher(b"k" * 32),
    )


def _record(
    vault: PostgresMemoryVault,
    *,
    subject_type: str = "project",
    subject_id: str = "project-1",
    data_scope: DataScope | None = None,
    now: datetime | None = None,
) -> EncryptedMemoryRecord:
    created_at = now or datetime.now(UTC)
    return vault._build_record(
        tenant_id="tenant-a",
        subject_type=subject_type,
        subject_id=subject_id,
        memory_type="preference",
        content="Use verified evidence",
        owner_id="user-1",
        classification="internal",
        write_policy="explicit_approval",
        confidence=Decimal("0.9"),
        source_refs=("run-1",),
        purpose="agent-context",
        data_scope=data_scope or _scope(),
        valid_until=created_at + timedelta(days=7),
        now=created_at,
        version=1,
    )


def test_memory_cipher_authenticates_envelope_context_and_key_size() -> None:
    with pytest.raises(ValueError, match="MEMORY_ENCRYPTION_KEY_INVALID"):
        AesGcmMemoryContentCipher(b"short")

    cipher = AesGcmMemoryContentCipher(b"k" * 32)
    nonce, ciphertext = cipher.encrypt(b"memory", associated_data=b"tenant-a")
    assert cipher.decrypt(nonce, ciphertext, associated_data=b"tenant-a") == b"memory"
    with pytest.raises(InvalidTag):
        cipher.decrypt(nonce, ciphertext, associated_data=b"tenant-b")


def test_build_record_validates_content_scope_and_retention_boundaries() -> None:
    vault = _vault()
    now = datetime.now(UTC)
    common: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "subject_type": "project",
        "subject_id": "project-1",
        "memory_type": "preference",
        "owner_id": "user-1",
        "classification": "internal",
        "write_policy": "explicit_approval",
        "confidence": Decimal("0.5"),
        "source_refs": (),
        "purpose": "context",
        "data_scope": _scope(),
        "valid_until": now + timedelta(days=1),
        "now": now,
        "version": 1,
    }
    for overrides, expected in (
        ({"content": " "}, "MEMORY_CONTENT_REQUIRED"),
        ({"content": "ok", "confidence": Decimal("1.1")}, "MEMORY_CONFIDENCE_OUT_OF_RANGE"),
        ({"content": "ok", "valid_until": now}, "MEMORY_VALID_UNTIL_INVALID"),
        ({"content": "ok", "purpose": " "}, "MEMORY_PURPOSE_REQUIRED"),
        ({"content": "ok", "version": 0}, "MEMORY_VERSION_INVALID"),
        ({"content": "ok", "classification": "unknown"}, "MEMORY_CLASSIFICATION_INVALID"),
        (
            {"content": "ok", "data_scope": _scope(tenant_id="tenant-b")},
            "MEMORY_DATA_SCOPE_TENANT_MISMATCH",
        ),
        (
            {
                "content": "ok",
                "classification": "confidential",
                "data_scope": _scope(),
            },
            "MEMORY_CLASSIFICATION_OUTSIDE_DATA_SCOPE",
        ),
    ):
        values = {**common, **overrides}
        with pytest.raises(ValueError, match=expected):
            vault._build_record(**values)

    record = vault._build_record(content="remember", **common)
    assert record.data_scope == _scope()
    assert record.version == 1
    assert record.content_hash


def test_memory_envelope_and_database_projection_round_trip() -> None:
    vault = _vault()
    record = _record(vault)
    database = vault._database_record(record)
    projected = vault._record(database)

    assert projected == record
    assert vault._to_view(projected).content == "Use verified evidence"
    assert vault._aad(record.tenant_id, record.memory_id, record.content_hash).startswith(
        b"tenant-a:"
    )

    packed = vault._pack(record.nonce, record.ciphertext)
    assert vault._unpack(packed) == (record.nonce, record.ciphertext)
    with pytest.raises(ValueError, match="MEMORY_CIPHER_NONCE_TOO_LARGE"):
        vault._pack(b"x" * 65_536, b"content")
    for invalid in (b"", b"wrong-prefix"):
        with pytest.raises(PlatformError, match="MEMORY_CIPHERTEXT_INVALID"):
            vault._unpack(invalid)
    with pytest.raises(PlatformError, match="MEMORY_CIPHERTEXT_INVALID"):
        vault._unpack(b"mem1" + (12).to_bytes(2, "big") + b"short")


def test_memory_integrity_rejects_ciphertext_and_content_hash_tampering() -> None:
    vault = _vault()
    record = _record(vault)
    tampered_ciphertext = copy.deepcopy(record)
    tampered_ciphertext.ciphertext = record.ciphertext[:-1] + bytes([record.ciphertext[-1] ^ 1])
    with pytest.raises(PlatformError, match="MEMORY_INTEGRITY_FAILURE"):
        vault._to_view(tampered_ciphertext)

    class _WrongPlaintextCipher:
        def encrypt(
            self,
            plaintext: bytes,
            *,
            associated_data: bytes,
        ) -> tuple[bytes, bytes]:
            return b"nonce", plaintext

        def decrypt(
            self,
            nonce: bytes,
            ciphertext: bytes,
            *,
            associated_data: bytes,
        ) -> bytes:
            return b"different content"

    wrong = PostgresMemoryVault(
        cast(Any, object()),
        cipher=_WrongPlaintextCipher(),
    )
    with pytest.raises(PlatformError, match="MEMORY_INTEGRITY_FAILURE"):
        wrong._to_view(record)


@pytest.mark.asyncio
async def test_write_requires_approval_and_persists_record_plus_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    with pytest.raises(PlatformError) as denied:
        await vault.write(
            tenant_id="tenant-a",
            subject_type="project",
            subject_id="project-1",
            memory_type="preference",
            content="remember",
            owner_id="user-1",
            classification="internal",
            write_policy="explicit_approval",
            approved=False,
        )
    assert denied.value.code == "MEMORY_WRITE_REQUIRES_APPROVAL"

    session = _Session()
    _patch_session(monkeypatch, session)
    record = await vault.write(
        tenant_id="tenant-a",
        subject_type="project",
        subject_id="project-1",
        memory_type="preference",
        content="remember",
        owner_id="user-1",
        classification="internal",
        write_policy="explicit_approval",
        approved=True,
        confidence=Decimal("0.8"),
        purpose="agent-context",
        data_scope=_scope(),
        now=datetime.now(UTC),
    )
    assert record.version == 1
    assert len(session.added) == 2
    assert session.flushes == session.commits == 1


@pytest.mark.asyncio
async def test_get_and_locked_record_enforce_tenant_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    record = _record(vault)
    row = vault._database_record(record)

    found = _Session(scalar_results=[row])
    _patch_session(monkeypatch, found)
    assert await vault.get(record.memory_id, record.tenant_id) == record

    missing = _Session(scalar_results=[None])
    _patch_session(monkeypatch, missing)
    with pytest.raises(NotFound):
        await vault.get(record.memory_id, record.tenant_id)

    assert (
        await vault._locked_record(
            cast(Any, _Session(scalar_results=[row])),
            record.memory_id,
            record.tenant_id,
        )
        is row
    )
    with pytest.raises(NotFound):
        await vault._locked_record(
            cast(Any, _Session(scalar_results=[None])),
            record.memory_id,
            record.tenant_id,
        )


@pytest.mark.asyncio
async def test_visible_and_context_queries_apply_scope_purpose_and_user_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    project = _record(vault)
    user_owned = _record(vault, subject_type="user", subject_id="user-1")
    other_user = _record(vault, subject_type="user", subject_id="user-2")
    rows = [
        vault._database_record(project),
        vault._database_record(user_owned),
        vault._database_record(other_user),
    ]

    with pytest.raises(PlatformError, match="MEMORY_QUERY_SCOPE_TENANT_MISMATCH"):
        await vault.list_visible(
            "tenant-a",
            "user-1",
            data_scope=_scope(tenant_id="tenant-b"),
        )

    session = _Session(scalars_results=[rows])
    _patch_session(monkeypatch, session)
    visible = await vault.list_visible(
        "tenant-a",
        "user-1",
        data_scope=_scope(),
        purpose="agent-context",
    )
    assert len(visible) == 3

    with pytest.raises(PlatformError, match="MEMORY_QUERY_SCOPE_TENANT_MISMATCH"):
        await vault.list_for_context(
            tenant_id="tenant-a",
            principal_id="user-1",
            data_scope=_scope(tenant_id="tenant-b"),
            purpose="agent-context",
        )
    with pytest.raises(ValueError, match="MEMORY_PURPOSE_REQUIRED"):
        await vault.list_for_context(
            tenant_id="tenant-a",
            principal_id="user-1",
            data_scope=_scope(),
            purpose=" ",
        )

    async def visible_stub(*_args: Any, **_kwargs: Any) -> tuple[Any, ...]:
        return visible

    monkeypatch.setattr(vault, "list_visible", visible_stub)
    contextual = await vault.list_for_context(
        tenant_id="tenant-a",
        principal_id="user-1",
        data_scope=_scope(),
        purpose=" agent-context ",
    )
    assert {item.subject_id for item in contextual} == {"project-1", "user-1"}


def test_scope_filter_fails_closed_for_classification_and_projection_mismatch() -> None:
    vault = _vault()
    record = _record(vault)
    assert vault._scope_allows(record, _scope()) is True

    invalid_classification = copy.deepcopy(record)
    invalid_classification.classification = "unknown"
    assert vault._scope_allows(invalid_classification, _scope()) is False
    assert (
        vault._scope_allows(
            record,
            _scope(classifications=frozenset({DataClassification.CONFIDENTIAL})),
        )
        is False
    )
    assert (
        vault._scope_allows(
            record,
            _scope(resource_ids=frozenset({"memory-1"})),
        )
        is False
    )

    row_filtered = _record(vault, data_scope=_scope(row_filter={"project": "1"}))
    assert vault._scope_allows(row_filtered, _scope()) is False
    field_limited = _record(vault, data_scope=_scope())
    assert (
        vault._scope_allows(
            field_limited,
            _scope(allowed_fields=frozenset({"summary"})),
        )
        is False
    )


@pytest.mark.asyncio
async def test_correction_supersedes_active_record_and_rejects_inactive_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    record = _record(vault)
    row = vault._database_record(record)
    with pytest.raises(ValueError, match="MEMORY_CORRECTION_REASON_REQUIRED"):
        await vault.correct(
            record.memory_id,
            tenant_id="tenant-a",
            actor_id="user-1",
            content="updated",
            reason=" ",
        )

    inactive = copy.copy(row)
    inactive.deleted_at = datetime.now(UTC)
    inactive_session = _Session(scalar_results=[inactive])
    _patch_session(monkeypatch, inactive_session)
    with pytest.raises(PlatformError, match="MEMORY_NOT_ACTIVE"):
        await vault.correct(
            record.memory_id,
            tenant_id="tenant-a",
            actor_id="user-1",
            content="updated",
            reason="correction",
        )

    active_session = _Session(scalar_results=[row])
    _patch_session(monkeypatch, active_session)
    replacement = await vault.correct(
        record.memory_id,
        tenant_id="tenant-a",
        actor_id="user-1",
        content="updated",
        reason="correction",
        now=record.valid_from + timedelta(minutes=1),
    )
    assert replacement.version == 2
    assert row.superseded_by == replacement.memory_id
    assert len(active_session.added_many) == 2
    assert active_session.commits == 1


@pytest.mark.asyncio
async def test_delete_is_idempotent_and_lifecycle_requires_visible_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _vault()
    record = _record(vault)
    row = vault._database_record(record)
    with pytest.raises(ValueError, match="MEMORY_DELETION_REASON_REQUIRED"):
        await vault.delete(
            record.memory_id,
            tenant_id="tenant-a",
            actor_id="user-1",
            reason=" ",
        )

    deleted_row = copy.copy(row)
    deleted_row.deleted_at = datetime.now(UTC)
    deleted_session = _Session(scalar_results=[deleted_row])
    _patch_session(monkeypatch, deleted_session)
    await vault.delete(
        record.memory_id,
        tenant_id="tenant-a",
        actor_id="user-1",
        reason="privacy request",
    )
    assert deleted_session.added == []
    assert deleted_session.commits == 1

    active_session = _Session(scalar_results=[row])
    _patch_session(monkeypatch, active_session)
    await vault.delete(
        record.memory_id,
        tenant_id="tenant-a",
        actor_id="user-1",
        reason="privacy request",
    )
    assert row.deleted_at is not None
    assert len(active_session.added) == 1

    missing_session = _Session(scalar_results=[None])
    _patch_session(monkeypatch, missing_session)
    with pytest.raises(NotFound):
        await vault.lifecycle("tenant-a", record.memory_id)

    event_row = vault._database_event(
        memory_id=record.memory_id,
        tenant_id="tenant-a",
        event_type="deleted",
        actor_id="user-1",
        reason="privacy request",
        previous_hash=record.content_hash,
        created_at=datetime.now(UTC),
    )
    lifecycle_session = _Session(
        scalar_results=[record.memory_id],
        scalars_results=[[event_row]],
    )
    _patch_session(monkeypatch, lifecycle_session)
    events = await vault.lifecycle("tenant-a", record.memory_id)
    assert len(events) == 1
    assert events[0].event_type == "deleted"


def test_lifecycle_event_projection_preserves_replacement_identity() -> None:
    vault = _vault()
    memory_id = uuid4()
    replacement_id = uuid4()
    now = datetime.now(UTC)
    row: DatabaseMemoryLifecycleEvent = vault._database_event(
        memory_id=memory_id,
        tenant_id="tenant-a",
        event_type="superseded",
        actor_id="user-1",
        reason="corrected",
        previous_hash="a" * 64,
        replacement_memory_id=replacement_id,
        created_at=now,
    )
    event = vault._event(row)
    assert event.memory_id == memory_id
    assert event.replacement_memory_id == replacement_id
    assert event.previous_hash == "a" * 64
