from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from agent_platform.application.records import ActionRecord


class KnowledgeSearchAdapter:
    """A source-backed reference adapter used by local and sandbox E2E flows."""

    def __init__(self, documents: list[dict[str, str]]) -> None:
        self._documents = tuple(dict(item) for item in documents)

    async def read(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> dict[str, Any]:
        del credential
        query = str(args["query"])
        normalized_query = query.casefold()
        limit = min(max(int(args.get("limit", 8)), 1), 20)
        matches = [
            item
            for item in self._documents
            if normalized_query in f"{item['title']} {item['content']}".casefold()
        ][:limit]
        captured_at = datetime.now(UTC).isoformat()
        items = [
            {
                **item,
                "captured_at": captured_at,
                "content_hash": hashlib.sha256(item["content"].encode()).hexdigest(),
                "trust": "untrusted",
            }
            for item in matches
        ]
        return {"items": items, "row_count": len(items), "query": query}

    async def preview(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> Mapping[str, Any]:
        del args, credential
        raise ValueError("READ_TOOL_HAS_NO_PREVIEW")

    async def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
        credential: Any,
    ) -> None:
        del idempotency_key, credential
        return None

    async def commit(
        self,
        payload: Mapping[str, Any],
        credential: Any,
        idempotency_key: str,
    ) -> Any:
        del payload, credential, idempotency_key
        raise ValueError("READ_TOOL_CANNOT_COMMIT")

    async def verify(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> Any:
        del action, receipt, credential
        raise ValueError("READ_TOOL_HAS_NO_SIDE_EFFECT")

    async def compensate(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> Any:
        del action, receipt, credential
        raise ValueError("READ_TOOL_HAS_NO_SIDE_EFFECT")


class SandboxEmailAdapter:
    """Medium/high Action sandbox with true idempotency and read-after-write."""

    def __init__(self, *, allowed_domains: set[str]) -> None:
        self._allowed_domains = frozenset(domain.casefold() for domain in allowed_domains)
        self._messages: dict[str, dict[str, Any]] = {}
        self.commit_count = 0

    def _validate(self, payload: Mapping[str, Any]) -> None:
        recipients = payload.get("recipients", [])
        if not recipients:
            raise ValueError("RECIPIENT_REQUIRED")
        for recipient in recipients:
            domain = str(recipient).rsplit("@", 1)[-1].casefold()
            if domain not in self._allowed_domains:
                raise ValueError(f"RECIPIENT_DOMAIN_DENIED: {domain}")
        if len(str(payload.get("subject", ""))) > 200:
            raise ValueError("EMAIL_SUBJECT_TOO_LONG")
        if len(str(payload.get("body", ""))) > 100_000:
            raise ValueError("EMAIL_BODY_TOO_LONG")

    async def read(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> dict[str, Any] | None:
        del credential
        key = str(args["idempotency_key"])
        return self._messages.get(key)

    async def preview(
        self,
        args: Mapping[str, Any],
        credential: Any,
    ) -> Mapping[str, Any]:
        del credential
        self._validate(args)
        return {
            "recipients": list(args["recipients"]),
            "subject": args["subject"],
            "body_preview": str(args["body"])[:500],
            "artifact_ids": list(args.get("artifact_ids", [])),
            "side_effect": "none_until_commit",
        }

    async def lookup_by_idempotency_key(
        self,
        idempotency_key: str,
        credential: Any,
    ) -> dict[str, Any] | None:
        del credential
        return self._messages.get(idempotency_key)

    async def commit(
        self,
        payload: Mapping[str, Any],
        credential: Any,
        idempotency_key: str,
    ) -> dict[str, Any]:
        del credential
        self._validate(payload)
        existing = self._messages.get(idempotency_key)
        if existing is not None:
            return existing
        self.commit_count += 1
        receipt = {
            "external_operation_id": f"sandbox-email-{uuid4()}",
            "committed_at": datetime.now(UTC).isoformat(),
            "result_summary": {
                "recipients": list(payload["recipients"]),
                "subject": payload["subject"],
                "status": "delivered_to_sandbox",
            },
            "idempotency_key": idempotency_key,
        }
        self._messages[idempotency_key] = receipt
        return receipt

    async def verify(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> dict[str, Any]:
        del action, credential
        key = self._receipt_key(receipt)
        stored = self._messages.get(key)
        return {
            "passed": stored == receipt,
            "verified_at": datetime.now(UTC).isoformat(),
            "method": "sandbox_read_after_write",
            "details": {
                "external_operation_id": (
                    receipt.get("external_operation_id") if isinstance(receipt, Mapping) else None
                ),
            },
        }

    async def compensate(
        self,
        action: ActionRecord,
        receipt: Any,
        credential: Any,
    ) -> dict[str, Any]:
        del action, credential
        removed = self._messages.pop(self._receipt_key(receipt), None)
        return {
            "compensated": removed is not None,
            "compensated_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def _receipt_key(receipt: object) -> str:
        if not isinstance(receipt, Mapping):
            raise ValueError("SANDBOX_RECEIPT_MAPPING_REQUIRED")
        key = receipt.get("idempotency_key")
        if not isinstance(key, str) or not key:
            raise ValueError("SANDBOX_RECEIPT_IDEMPOTENCY_KEY_REQUIRED")
        return key
