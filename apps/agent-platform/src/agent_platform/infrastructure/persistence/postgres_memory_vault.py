"""RLS-protected, encrypted long-term memory backed by PostgreSQL."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime
from decimal import Decimal
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.application.memory import MemoryView
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope
from agent_platform.infrastructure.memory_vault import (
    EncryptedMemoryRecord,
    MemoryLifecycleEvent,
)
from agent_platform.infrastructure.persistence.models import (
    MemoryLifecycleEvent as DatabaseMemoryLifecycleEvent,
)
from agent_platform.infrastructure.persistence.models import (
    MemoryRecord,
)
from agent_platform.infrastructure.persistence.session import (
    AsyncSessionFactory,
    tenant_session,
)


class MemoryContentCipher(Protocol):
    """Envelope cipher port; a KMS adapter may implement the same contract."""

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> tuple[bytes, bytes]: ...

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        *,
        associated_data: bytes,
    ) -> bytes: ...


class AesGcmMemoryContentCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) not in {16, 24, 32}:
            raise ValueError("MEMORY_ENCRYPTION_KEY_INVALID")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        return nonce, self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        *,
        associated_data: bytes,
    ) -> bytes:
        return self._cipher.decrypt(nonce, ciphertext, associated_data)


class PostgresMemoryVault:
    _ENVELOPE_PREFIX = b"mem1"

    def __init__(
        self,
        factory: AsyncSessionFactory,
        *,
        cipher: MemoryContentCipher,
    ) -> None:
        self._factory = factory
        self._cipher = cipher

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
        created_at = now or datetime.now(UTC)
        record = self._build_record(
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
            now=created_at,
            version=1,
        )
        async with tenant_session(self._factory, tenant_id) as session:
            session.add(self._database_record(record))
            await session.flush()
            session.add(
                self._database_event(
                    memory_id=record.memory_id,
                    tenant_id=tenant_id,
                    event_type="created",
                    actor_id=owner_id,
                    reason="Approved memory write.",
                    created_at=created_at,
                )
            )
            await session.commit()
        return record

    async def get(
        self,
        memory_id: UUID,
        tenant_id: str,
    ) -> EncryptedMemoryRecord:
        async with tenant_session(self._factory, tenant_id) as session:
            row = await session.scalar(
                select(MemoryRecord).where(
                    MemoryRecord.memory_id == memory_id,
                    MemoryRecord.tenant_id == tenant_id,
                )
            )
            if row is None:
                raise NotFound("memory", str(memory_id))
            return self._record(row)

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
        conditions = [
            MemoryRecord.tenant_id == tenant_id,
            MemoryRecord.owner_id == owner_id,
            MemoryRecord.deleted_at.is_(None),
            MemoryRecord.superseded_by.is_(None),
            MemoryRecord.valid_from <= current,
            MemoryRecord.valid_until.is_(None) | (MemoryRecord.valid_until > current),
        ]
        if purpose is not None:
            conditions.append(MemoryRecord.purpose == purpose)
        async with tenant_session(self._factory, tenant_id) as session:
            rows = (
                await session.scalars(
                    select(MemoryRecord)
                    .where(*conditions)
                    .order_by(
                        MemoryRecord.valid_from,
                        MemoryRecord.memory_version,
                        MemoryRecord.memory_id,
                    )
                )
            ).all()
            records = tuple(self._record(row) for row in rows)
        return tuple(
            self._to_view(record)
            for record in records
            if data_scope is None or self._scope_allows(record, data_scope)
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
        changed_at = now or datetime.now(UTC)
        async with tenant_session(self._factory, tenant_id) as session:
            original = await self._locked_record(session, memory_id, tenant_id)
            if (
                original.deleted_at is not None
                or original.superseded_by is not None
                or original.valid_from > changed_at
                or (original.valid_until is not None and original.valid_until <= changed_at)
            ):
                raise PlatformError(
                    "MEMORY_NOT_ACTIVE",
                    "Only active memory can be corrected",
                    http_status=409,
                )
            replacement = self._build_record(
                tenant_id=original.tenant_id,
                subject_type=original.subject_type,
                subject_id=original.subject_id,
                memory_type=original.memory_type,
                content=content,
                owner_id=original.owner_id,
                classification=original.classification,
                write_policy=original.write_policy,
                confidence=original.confidence,
                source_refs=tuple(str(value) for value in original.source_refs),
                purpose=original.purpose,
                data_scope=DataScope.model_validate(original.data_scope),
                valid_until=original.valid_until,
                now=changed_at,
                version=original.memory_version + 1,
            )
            session.add(self._database_record(replacement))
            await session.flush()
            original.superseded_by = replacement.memory_id
            session.add_all(
                [
                    self._database_event(
                        memory_id=replacement.memory_id,
                        tenant_id=tenant_id,
                        event_type="corrected",
                        actor_id=actor_id,
                        reason=reason,
                        previous_hash=original.content_hash,
                        created_at=changed_at,
                    ),
                    self._database_event(
                        memory_id=memory_id,
                        tenant_id=tenant_id,
                        event_type="superseded",
                        actor_id=actor_id,
                        reason=reason,
                        previous_hash=original.content_hash,
                        replacement_memory_id=replacement.memory_id,
                        created_at=changed_at,
                    ),
                ]
            )
            await session.commit()
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
        deleted_at = now or datetime.now(UTC)
        async with tenant_session(self._factory, tenant_id) as session:
            record = await self._locked_record(session, memory_id, tenant_id)
            if record.deleted_at is not None:
                await session.commit()
                return
            record.deleted_at = deleted_at
            session.add(
                self._database_event(
                    memory_id=memory_id,
                    tenant_id=tenant_id,
                    event_type="deleted",
                    actor_id=actor_id,
                    reason=reason,
                    previous_hash=record.content_hash,
                    created_at=deleted_at,
                )
            )
            await session.commit()

    async def lifecycle(
        self,
        tenant_id: str,
        memory_id: UUID,
    ) -> tuple[MemoryLifecycleEvent, ...]:
        async with tenant_session(self._factory, tenant_id) as session:
            visible = await session.scalar(
                select(MemoryRecord.memory_id).where(
                    MemoryRecord.memory_id == memory_id,
                    MemoryRecord.tenant_id == tenant_id,
                )
            )
            if visible is None:
                raise NotFound("memory", str(memory_id))
            rows = (
                await session.scalars(
                    select(DatabaseMemoryLifecycleEvent)
                    .where(
                        DatabaseMemoryLifecycleEvent.memory_id == memory_id,
                        DatabaseMemoryLifecycleEvent.tenant_id == tenant_id,
                    )
                    .order_by(
                        DatabaseMemoryLifecycleEvent.created_at,
                        DatabaseMemoryLifecycleEvent.event_id,
                    )
                )
            ).all()
            return tuple(self._event(row) for row in rows)

    async def _locked_record(
        self,
        session: AsyncSession,
        memory_id: UUID,
        tenant_id: str,
    ) -> MemoryRecord:
        row = await session.scalar(
            select(MemoryRecord)
            .where(
                MemoryRecord.memory_id == memory_id,
                MemoryRecord.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if row is None:
            raise NotFound("memory", str(memory_id))
        return row

    def _build_record(
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
    ) -> EncryptedMemoryRecord:
        if not content.strip():
            raise ValueError("MEMORY_CONTENT_REQUIRED")
        if confidence is not None and not Decimal("0") <= confidence <= Decimal("1"):
            raise ValueError("MEMORY_CONFIDENCE_OUT_OF_RANGE")
        if valid_until is not None and valid_until <= now:
            raise ValueError("MEMORY_VALID_UNTIL_INVALID")
        normalized_purpose = purpose.strip()
        if not normalized_purpose:
            raise ValueError("MEMORY_PURPOSE_REQUIRED")
        if version < 1:
            raise ValueError("MEMORY_VERSION_INVALID")
        normalized_classification = self._classification(classification)
        normalized_scope = self._validated_scope(
            tenant_id=tenant_id,
            classification=normalized_classification,
            data_scope=data_scope,
        )
        memory_id = uuid4()
        digest = hashlib.sha256(content.encode()).hexdigest()
        aad = self._aad(tenant_id, memory_id, digest)
        nonce, ciphertext = self._cipher.encrypt(
            content.encode(),
            associated_data=aad,
        )
        return EncryptedMemoryRecord(
            memory_id=memory_id,
            tenant_id=tenant_id,
            subject_type=subject_type,
            subject_id=subject_id,
            memory_type=memory_type,
            ciphertext=ciphertext,
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

    def _to_view(self, record: EncryptedMemoryRecord) -> MemoryView:
        try:
            plaintext = self._cipher.decrypt(
                record.nonce,
                record.ciphertext,
                associated_data=self._aad(
                    record.tenant_id,
                    record.memory_id,
                    record.content_hash,
                ),
            )
            content = plaintext.decode()
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise PlatformError(
                "MEMORY_INTEGRITY_FAILURE",
                "Memory content failed integrity verification",
                http_status=503,
            ) from exc
        if hashlib.sha256(content.encode()).hexdigest() != record.content_hash:
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

    def _database_record(self, record: EncryptedMemoryRecord) -> MemoryRecord:
        return MemoryRecord(
            memory_id=record.memory_id,
            tenant_id=record.tenant_id,
            subject_type=record.subject_type,
            subject_id=record.subject_id,
            memory_type=record.memory_type,
            content_encrypted=self._pack(record.nonce, record.ciphertext),
            content_hash=record.content_hash,
            source_refs=list(record.source_refs),
            classification=record.classification,
            confidence=record.confidence,
            owner_id=record.owner_id,
            write_policy=record.write_policy,
            purpose=record.purpose,
            data_scope=record.data_scope.model_dump(mode="json"),
            memory_version=record.version,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
            superseded_by=record.superseded_by,
            deleted_at=record.deleted_at,
            created_at=record.valid_from,
        )

    def _record(self, row: MemoryRecord) -> EncryptedMemoryRecord:
        nonce, ciphertext = self._unpack(row.content_encrypted)
        return EncryptedMemoryRecord(
            memory_id=row.memory_id,
            tenant_id=row.tenant_id,
            subject_type=row.subject_type,
            subject_id=row.subject_id,
            memory_type=row.memory_type,
            ciphertext=ciphertext,
            nonce=nonce,
            content_hash=row.content_hash,
            classification=row.classification,
            owner_id=row.owner_id,
            write_policy=row.write_policy,
            confidence=row.confidence,
            source_refs=tuple(str(value) for value in row.source_refs),
            purpose=row.purpose,
            data_scope=DataScope.model_validate(row.data_scope),
            version=row.memory_version,
            valid_from=row.valid_from,
            valid_until=row.valid_until,
            superseded_by=row.superseded_by,
            deleted_at=row.deleted_at,
        )

    @staticmethod
    def _database_event(
        *,
        memory_id: UUID,
        tenant_id: str,
        event_type: str,
        actor_id: str,
        reason: str,
        created_at: datetime,
        previous_hash: str | None = None,
        replacement_memory_id: UUID | None = None,
    ) -> DatabaseMemoryLifecycleEvent:
        return DatabaseMemoryLifecycleEvent(
            event_id=uuid4(),
            memory_id=memory_id,
            tenant_id=tenant_id,
            event_type=event_type,
            actor_id=actor_id,
            reason=reason,
            previous_hash=previous_hash,
            replacement_memory_id=replacement_memory_id,
            metadata_json={},
            created_at=created_at,
        )

    @staticmethod
    def _event(row: DatabaseMemoryLifecycleEvent) -> MemoryLifecycleEvent:
        return MemoryLifecycleEvent(
            event_id=row.event_id,
            memory_id=row.memory_id,
            tenant_id=row.tenant_id,
            event_type=row.event_type,
            actor_id=row.actor_id,
            reason=row.reason,
            previous_hash=row.previous_hash,
            replacement_memory_id=row.replacement_memory_id,
            created_at=row.created_at,
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

    @classmethod
    def _pack(cls, nonce: bytes, ciphertext: bytes) -> bytes:
        if len(nonce) > 65_535:
            raise ValueError("MEMORY_CIPHER_NONCE_TOO_LARGE")
        return cls._ENVELOPE_PREFIX + len(nonce).to_bytes(2, "big") + nonce + ciphertext

    @classmethod
    def _unpack(cls, envelope: bytes) -> tuple[bytes, bytes]:
        prefix_length = len(cls._ENVELOPE_PREFIX)
        if len(envelope) < prefix_length + 2 or not envelope.startswith(cls._ENVELOPE_PREFIX):
            raise PlatformError(
                "MEMORY_CIPHERTEXT_INVALID",
                "Stored memory ciphertext envelope is invalid",
                http_status=503,
            )
        nonce_length = int.from_bytes(envelope[prefix_length : prefix_length + 2], "big")
        nonce_start = prefix_length + 2
        nonce_end = nonce_start + nonce_length
        if nonce_end >= len(envelope):
            raise PlatformError(
                "MEMORY_CIPHERTEXT_INVALID",
                "Stored memory ciphertext envelope is truncated",
                http_status=503,
            )
        return envelope[nonce_start:nonce_end], envelope[nonce_end:]

    @staticmethod
    def _aad(tenant_id: str, memory_id: UUID, digest: str) -> bytes:
        return f"{tenant_id}:{memory_id}:{digest}".encode()
