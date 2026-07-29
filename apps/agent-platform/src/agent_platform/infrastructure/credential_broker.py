from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True, slots=True)
class WorkloadCredentialGrant:
    """Short-lived descriptor exchanged by an adapter using workload identity."""

    tenant_id: str
    principal_id: str
    scopes: frozenset[str]
    secret_reference: str
    issued_at: datetime
    expires_at: datetime


class ReferencedCredentialBroker:
    """Issue bounded grants without resolving long-lived business credentials."""

    def __init__(self, secret_reference: str) -> None:
        normalized = secret_reference.strip()
        if not normalized:
            raise ValueError("CREDENTIAL_SECRET_REFERENCE_REQUIRED")
        self._secret_reference = normalized

    async def issue(
        self,
        tenant_id: str,
        principal_id: str,
        scopes: frozenset[str],
        ttl_seconds: int,
    ) -> WorkloadCredentialGrant:
        if not tenant_id.strip() or not principal_id.strip():
            raise ValueError("CREDENTIAL_SUBJECT_REQUIRED")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("CREDENTIAL_TTL_OUT_OF_RANGE")
        issued_at = datetime.now(UTC)
        return WorkloadCredentialGrant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            scopes=scopes,
            secret_reference=self._secret_reference,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )
