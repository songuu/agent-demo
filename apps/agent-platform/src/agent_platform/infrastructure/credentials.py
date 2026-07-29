"""Short-lived, scope-bound credential grants.

The broker deliberately returns a grant descriptor rather than a reusable
provider token. Production brokers exchange the descriptor inside an adapter
call using workload identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True, slots=True)
class EphemeralCredential:
    tenant_id: str
    principal_id: str
    scopes: frozenset[str]
    issued_at: datetime
    expires_at: datetime


class EphemeralCredentialBroker:
    async def issue(
        self,
        tenant_id: str,
        principal_id: str,
        scopes: frozenset[str],
        ttl_seconds: int,
    ) -> EphemeralCredential:
        if ttl_seconds < 1 or ttl_seconds > 300:
            raise ValueError("CREDENTIAL_TTL_OUT_OF_RANGE")
        issued_at = datetime.now(UTC)
        return EphemeralCredential(
            tenant_id=tenant_id,
            principal_id=principal_id,
            scopes=scopes,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=ttl_seconds),
        )
