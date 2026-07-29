from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain.hashing import (
    business_idempotency_key,
    canonical_json,
    payload_hash,
)


class CanonicalHashTests(unittest.TestCase):
    def test_canonical_json_is_stable_across_key_and_set_order(self) -> None:
        first = {
            "z": {"b", "a"},
            "amount": Decimal("8.00"),
            "id": UUID("00000000-0000-0000-0000-000000000001"),
            "at": datetime(2026, 7, 23, 8, 0, tzinfo=UTC),
            "nested": {"b": 2, "a": 1},
        }
        second = {
            "nested": {"a": 1, "b": 2},
            "at": datetime(2026, 7, 23, 8, 0, tzinfo=UTC),
            "id": UUID("00000000-0000-0000-0000-000000000001"),
            "amount": Decimal("8.00"),
            "z": {"a", "b"},
        }
        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertNotIn(" ", canonical_json(first))
        self.assertIn('"amount":"8.00"', canonical_json(first))

    def test_payload_hash_is_sha256_and_changes_with_payload(self) -> None:
        digest = payload_hash({"recipient": "a@example.test", "subject": "A"})
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            digest,
            payload_hash({"recipient": "a@example.test", "subject": "B"}),
        )

    def test_business_idempotency_key_includes_tenant_action_and_window(self) -> None:
        payload = {"recipient": "a@example.test"}
        first = business_idempotency_key(
            tenant_id="tenant-1",
            action_type="email.send",
            payload=payload,
            business_window="2026-07-23",
        )
        same = business_idempotency_key(
            tenant_id="tenant-1",
            action_type="email.send",
            payload={"recipient": "a@example.test"},
            business_window="2026-07-23",
        )
        other_tenant = business_idempotency_key(
            tenant_id="tenant-2",
            action_type="email.send",
            payload=payload,
            business_window="2026-07-23",
        )
        self.assertEqual(first, same)
        self.assertNotEqual(first, other_tenant)
        self.assertRegex(first, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
