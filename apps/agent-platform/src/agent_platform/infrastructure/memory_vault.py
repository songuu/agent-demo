"""Governed long-term memory with encryption and explicit lifecycle events."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.application.memory import MemoryView
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope


@dataclass(slots=True)
class EncryptedMemoryRecord:
    memory_id: UUID
    tenant_id: str
    subject_type: str
    subject_id: str
    memory_type: str
    ciphertext: bytes
    nonce: bytes
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
    superseded_by: UUID | None = None
    deleted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class MemoryLifecycleEvent:
    event_id: UUID
    memory_id: UUID
    tenant_id: str
    event_type: str
    actor_id: str
    reason: str
    previous_hash: str | None = None
    replacement_memory_id: UUID | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class MemoryVault:
    """Reference vault used by local mode and as a production adapter contract."""

    def __init__(self, *, encryption_key: bytes) -> None:
        if len(encryption_key) not in {16, 24, 32}:
            raise ValueError("MEMORY_ENCRYPTION_KEY_INVALID")
        self._cipher = AESGCM(encryption_key)
        self._records: dict[UUID, EncryptedMemoryRecord] = {}
        self._events: dict[UUID, list[MemoryLifecycleEvent]] = {}

    async def write(
        self,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        memory_type: str,
        content: str,
        owner_id: str,
        classification: str,
        write_policy: str,
        approved: bool,
        confidence: Decimal | None = None,
        source_refs: tuple[str, ...] = (),
        valid_until: datetime | None = None,
        purpose: str = "general",
        data_scope: DataScope | None = None,
        now: datetime | None = None,
    ) -> EncryptedMemoryRecord:
        if not approved:
            raise PlatformError(
                "MEMORY_WRITE_REQUIRES_APPROVAL",
                "Long-term memory requires an explicit write policy decision",
                http_status=403,
            )
        written_at = now or datetime.now(UTC)
        return self._write(
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            memory_type=memory_type,
            content=content,
            owner_id=owner_id,
            classification=classification,
            write_policy=write_policy,
            confidence=confidence,
            source_refs=source_refs,
            purpose=purpose,
            data_scope=data_scope,
            valid_until=valid_until,
            now=written_at,
            version=1,
            lifecycle_type="created",
            lifecycle_actor_id=owner_id,
            lifecycle_reason="Approved memory write.",
        )

    async def get(
        self,
        memory_id: UUID,
        tenant_id: str,
    ) -> EncryptedMemoryRecord:
        record = self._records.get(memory_id)
        if record is None or record.tenant_id != tenant_id:
            raise NotFound("memory", str(memory_id))
        return record

    async def list_visible(
        self,
        tenant_id: str,
        owner_id: str,
        *,
        data_scope: DataScope | None = None,
        purpose: str | None = None,
        now: datetime | None = None,
    ) -> tuple[MemoryView, ...]:
        if data_scope is not None and data_scope.tenant_id != tenant_id:
            raise PlatformError(
                "MEMORY_QUERY_SCOPE_TENANT_MISMATCH",
                "Memory query data scope must match the requested tenant",
                http_status=403,
            )
        current = now or datetime.now(UTC)
        visible = [
            self._to_view(record)
            for record in self._records.values()
            if self._is_active(record, current)
            and record.tenant_id == tenant_id
            and record.owner_id == owner_id
            and (purpose is None or record.purpose == purpose)
            and (data_scope is None or self._scope_allows(record, data_scope))
        ]
        return tuple(
            sorted(
                visible,
                key=lambda item: (item.valid_from, item.version, str(item.memory_id)),
            )
        )

    async def list_for_context(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        data_scope: DataScope,
        purpose: str,
        now: datetime | None = None,
    ) -> tuple[MemoryView, ...]:
        if data_scope.tenant_id != tenant_id:
            raise PlatformError(
                "MEMORY_QUERY_SCOPE_TENANT_MISMATCH",
                "Memory query data scope must match the requested tenant",
                http_status=403,
            )
        normalized_purpose = purpose.strip()
        if not normalized_purpose:
            raise ValueError("MEMORY_PURPOSE_REQUIRED")
        visible = await self.list_visible(
            tenant_id,
            principal_id,
            data_scope=data_scope,
            purpose=normalized_purpose,
            now=now,
        )
        return tuple(
            item
            for item in visible
            if item.subject_type != "user" or item.subject_id == principal_id
        )

    async def correct(
        self,
        memory_id: UUID,
        *,
        tenant_id: str,
        actor_id: str,
        content: str,
        reason: str,
        now: datetime | None = None,
    ) -> EncryptedMemoryRecord:
        if not reason.strip():
            raise ValueError("MEMORY_CORRECTION_REASON_REQUIRED")
        if not actor_id.strip():
            raise ValueError("MEMORY_ACTOR_REQUIRED")
        original = await self.get(memory_id, tenant_id)
        if original.deleted_at is not None or original.superseded_by is not None:
            raise PlatformError(
                "MEMORY_NOT_ACTIVE",
                "Only active memory can be corrected",
                http_status=409,
            )
        changed_at = now or datetime.now(UTC)
        if not self._is_active(original, changed_at):
            raise PlatformError(
                "MEMORY_NOT_ACTIVE",
                "Only active memory can be corrected",
                http_status=409,
            )
        replacement = self._write(
            tenant_id=original.tenant_id,
            subject_type=original.subject_type,
            subject_id=original.subject_id,
            memory_type=original.memory_type,
            content=content,
            owner_id=original.owner_id,
            classification=original.classification,
            write_policy=original.write_policy,
            confidence=original.confidence,
            source_refs=original.source_refs,
            purpose=original.purpose,
            data_scope=original.data_scope,
            valid_until=original.valid_until,
            now=changed_at,
            version=original.version + 1,
            lifecycle_type="corrected",
            lifecycle_actor_id=actor_id,
            lifecycle_reason=reason,
            previous_hash=original.content_hash,
        )
        original.superseded_by = replacement.memory_id
        self._events[memory_id].append(
            MemoryLifecycleEvent(
                event_id=uuid4(),
                memory_id=memory_id,
                tenant_id=tenant_id,
                event_type="superseded",
                actor_id=actor_id,
                reason=reason,
                previous_hash=original.content_hash,
                replacement_memory_id=replacement.memory_id,
                created_at=changed_at,
            )
        )
        return replacement

    async def delete(
        self,
        memory_id: UUID,
        *,
        tenant_id: str,
        actor_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> None:
        if not reason.strip():
            raise ValueError("MEMORY_DELETION_REASON_REQUIRED")
        if not actor_id.strip():
            raise ValueError("MEMORY_ACTOR_REQUIRED")
        record = await self.get(memory_id, tenant_id)
        if record.deleted_at is not None:
            return
        deleted_at = now or datetime.now(UTC)
        record.deleted_at = deleted_at
        self._events[memory_id].append(
            MemoryLifecycleEvent(
                event_id=uuid4(),
                memory_id=memory_id,
                tenant_id=tenant_id,
                event_type="deleted",
                actor_id=actor_id,
                reason=reason,
                previous_hash=record.content_hash,
                created_at=deleted_at,
            )
        )

    async def lifecycle(
        self,
        tenant_id: str,
        memory_id: UUID,
    ) -> tuple[MemoryLifecycleEvent, ...]:
        await self.get(memory_id, tenant_id)
        return tuple(self._events[memory_id])

    def _write(
        self,
        *,
        tenant_id: str,
        subject_type: str,
        subject_id: str,
        memory_type: str,
        content: str,
        owner_id: str,
        classification: str,
        write_policy: str,
        confidence: Decimal | None,
        source_refs: tuple[str, ...],
        purpose: str,
        data_scope: DataScope | None,
        valid_until: datetime | None,
        now: datetime,
        version: int,
        lifecycle_type: str,
        lifecycle_actor_id: str,
        lifecycle_reason: str,
        previous_hash: str | None = None,
    ) -> EncryptedMemoryRecord:
        if not content.strip():
            raise ValueError("MEMORY_CONTENT_REQUIRED")
        normalized_purpose = purpose.strip()
        if not normalized_purpose:
            raise ValueError("MEMORY_PURPOSE_REQUIRED")
        if confidence is not None and not Decimal("0") <= confidence <= Decimal("1"):
            raise ValueError("MEMORY_CONFIDENCE_OUT_OF_RANGE")
        if valid_until is not None and valid_until <= now:
            raise ValueError("MEMORY_VALID_UNTIL_INVALID")
        if version < 1:
            raise ValueError("MEMORY_VERSION_INVALID")
        normalized_classification = self._classification(classification)
        normalized_scope = self._validated_scope(
            tenant_id=tenant_id,
            classification=normalized_classification,
            data_scope=data_scope,
        )
        memory_id = uuid4()
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        nonce = os.urandom(12)
        associated_data = f"{tenant_id}:{memory_id}:{digest}".encode()
        record = EncryptedMemoryRecord(
            memory_id=memory_id,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            memory_type=memory_type,
            ciphertext=self._cipher.encrypt(
                nonce,
                content.encode("utf-8"),
                associated_data,
            ),
            nonce=nonce,
            content_hash=digest,
            classification=normalized_classification.value,
            owner_id=owner_id,
            write_policy=write_policy,
            confidence=confidence,
            source_refs=source_refs,
            purpose=normalized_purpose,
            data_scope=normalized_scope,
            version=version,
            valid_from=now,
            valid_until=valid_until,
        )
        self._records[memory_id] = record
        self._events[memory_id] = [
            MemoryLifecycleEvent(
                event_id=uuid4(),
                memory_id=memory_id,
                tenant_id=tenant_id,
                event_type=lifecycle_type,
                actor_id=lifecycle_actor_id,
                reason=lifecycle_reason,
                previous_hash=previous_hash,
                created_at=now,
            )
        ]
        return record

    def _to_view(self, record: EncryptedMemoryRecord) -> MemoryView:
        associated_data = f"{record.tenant_id}:{record.memory_id}:{record.content_hash}".encode()
        content = self._cipher.decrypt(
            record.nonce,
            record.ciphertext,
            associated_data,
        ).decode("utf-8")
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != record.content_hash:
            raise PlatformError(
                "MEMORY_INTEGRITY_FAILURE",
                "Memory content failed integrity verification",
                http_status=503,
            )
        return MemoryView(
            memory_id=record.memory_id,
            tenant_id=record.tenant_id,
            subject_type=record.subject_type,
            subject_id=record.subject_id,
            memory_type=record.memory_type,
            content=content,
            content_hash=record.content_hash,
            classification=record.classification,
            owner_id=record.owner_id,
            write_policy=record.write_policy,
            confidence=record.confidence,
            source_refs=record.source_refs,
            purpose=record.purpose,
            data_scope=record.data_scope,
            version=record.version,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
        )

    @staticmethod
    def _is_active(record: EncryptedMemoryRecord, now: datetime) -> bool:
        return (
            record.deleted_at is None
            and record.superseded_by is None
            and record.valid_from <= now
            and (record.valid_until is None or record.valid_until > now)
        )

    @staticmethod
    def _scope_allows(record: EncryptedMemoryRecord, requested: DataScope) -> bool:
        try:
            classification = DataClassification(record.classification)
        except ValueError:
            return False
        if classification not in requested.classifications:
            return False
        stored = record.data_scope
        if requested.resource_ids and not stored.resource_ids:
            return False
        if not stored.is_subset_of(requested):
            return False
        if stored.row_filter != requested.row_filter:
            return False
        if requested.allowed_fields and not stored.allowed_fields:
            return False
        return True

    @staticmethod
    def _classification(value: str) -> DataClassification:
        try:
            return DataClassification(value)
        except ValueError as exc:
            raise ValueError("MEMORY_CLASSIFICATION_INVALID") from exc

    @staticmethod
    def _validated_scope(
        *,
        tenant_id: str,
        classification: DataClassification,
        data_scope: DataScope | None,
    ) -> DataScope:
        scope = data_scope or DataScope(
            tenant_id=tenant_id,
            resource_types={"memory"},
            classifications={classification},
        )
        if scope.tenant_id != tenant_id:
            raise ValueError("MEMORY_DATA_SCOPE_TENANT_MISMATCH")
        if classification not in scope.classifications:
            raise ValueError("MEMORY_CLASSIFICATION_OUTSIDE_DATA_SCOPE")
        return scope
