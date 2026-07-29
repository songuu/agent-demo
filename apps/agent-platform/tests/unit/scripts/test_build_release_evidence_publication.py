from __future__ import annotations

import json
from argparse import Namespace
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments


def _mutate_receipt(
    args: Namespace,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    path = args.published_assets
    receipt = json.loads(path.read_text(encoding="utf-8"))
    mutation(receipt)
    path.write_text(json.dumps(receipt), encoding="utf-8")


def test_release_evidence_rejects_missing_published_asset(tmp_path: Path) -> None:
    args = _arguments(tmp_path)
    _mutate_receipt(args, lambda receipt: receipt["assets"].pop("canary"))

    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_ASSET_SET_MISMATCH"):
        build_evidence(args)


def test_release_evidence_rejects_publication_identity_mismatch(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)

    def mismatch(receipt: dict[str, object]) -> None:
        receipt["image_digest"] = "sha256:" + "9" * 64

    _mutate_receipt(args, mismatch)
    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_IDENTITY_MISMATCH"):
        build_evidence(args)


def test_release_evidence_rejects_short_publication_retention(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)

    def shorten(receipt: dict[str, object]) -> None:
        published_at = datetime.fromisoformat(str(receipt["published_at"]))
        receipt["assets"]["sbom"]["object_retain_until"] = (
            (published_at + timedelta(days=364)).astimezone(UTC).isoformat()
        )

    _mutate_receipt(args, shorten)
    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_RETENTION_TOO_SHORT"):
        build_evidence(args)


def test_release_evidence_rejects_digest_uri_mismatch(tmp_path: Path) -> None:
    args = _arguments(tmp_path)

    def mismatch(receipt: dict[str, object]) -> None:
        receipt["assets"]["sbom"]["sha256"] = "sha256:" + "f" * 64

    _mutate_receipt(args, mismatch)
    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_DIGEST_URI_MISMATCH"):
        build_evidence(args)


def test_release_evidence_ignores_untrusted_legacy_uri_arguments(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)
    args.sbom_uri = "https://attacker.invalid/mutable"
    args.provenance_uri = "https://attacker.invalid/mutable"

    evidence = build_evidence(args)

    assert "attacker.invalid" not in evidence["sbom_uri"]
    assert "attacker.invalid" not in evidence["provenance_uri"]
    assert (
        evidence["approvals_bundle_uri"]
        == (evidence["evidence_publication"]["assets"]["release_approvals"]["content_uri"])
    )
