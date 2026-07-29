from __future__ import annotations

from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_approvals import _arguments
from tests.unit.scripts.test_build_release_evidence_publication import _mutate_receipt


def test_release_evidence_rejects_asset_release_binding_mismatch(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)

    def mismatch(receipt: dict[str, object]) -> None:
        receipt["assets"]["sbom"]["release_binding"]["git_sha"] = "c" * 40

    _mutate_receipt(args, mismatch)
    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_RELEASE_BINDING_MISMATCH"):
        build_evidence(args)


def test_release_evidence_rejects_short_asset_retention_policy(
    tmp_path: Path,
) -> None:
    args = _arguments(tmp_path)

    def shorten(receipt: dict[str, object]) -> None:
        receipt["assets"]["sbom"]["retention_policy"] = "release-evidence@1:immutable:364d"

    _mutate_receipt(args, shorten)
    with pytest.raises(ValueError, match="PUBLISHED_EVIDENCE_RETENTION_POLICY_INVALID"):
        build_evidence(args)
