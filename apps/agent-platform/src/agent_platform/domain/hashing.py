"""Canonical hashing used for approvals, audit evidence, and idempotency."""

from __future__ import annotations

import base64
import json
import math
from collections.abc import Mapping, Sequence, Set
from dataclasses import asdict, is_dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import UUID

from pydantic import BaseModel


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("CANONICAL_JSON_NON_FINITE_NUMBER: NaN and infinity are forbidden")
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("CANONICAL_JSON_NON_FINITE_NUMBER: Decimal must be finite")
        # Decimal remains a string so financial precision and trailing zeros survive.
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("TIMEZONE_REQUIRED: canonical datetime must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, bytes):
        return {"$bytes_base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("CANONICAL_JSON_STRING_KEY_REQUIRED: object keys must be strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        items = [_normalize(item) for item in value]
        return sorted(items, key=_dump_normalized)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    raise TypeError(f"CANONICAL_JSON_UNSUPPORTED_TYPE: cannot canonicalize {type(value).__name__}")


def _dump_normalized(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_json(value: Any) -> str:
    """Return deterministic UTF-8 JSON without lossy numeric coercion."""
    return _dump_normalized(_normalize(value))


def payload_hash(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def business_idempotency_key(
    *,
    tenant_id: str,
    action_type: str,
    payload: Any,
    business_window: str,
) -> str:
    """Bind duplicate suppression to tenant, operation, payload, and business window."""
    if not tenant_id.strip():
        raise ValueError("IDEMPOTENCY_TENANT_REQUIRED: tenant_id must not be empty")
    if not action_type.strip():
        raise ValueError("IDEMPOTENCY_ACTION_REQUIRED: action_type must not be empty")
    if not business_window.strip():
        raise ValueError("IDEMPOTENCY_WINDOW_REQUIRED: business_window must not be empty")
    return payload_hash(
        {
            "action_type": action_type,
            "business_window": business_window,
            "payload": payload,
            "tenant_id": tenant_id,
        }
    )
