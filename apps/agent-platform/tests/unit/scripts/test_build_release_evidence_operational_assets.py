from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from scripts.build_release_evidence import build_evidence
from tests.unit.scripts.test_build_release_evidence_readiness import (
    _readiness_arguments,
)


def _published_receipt(args) -> dict[str, object]:
    return json.loads(args.published_assets.read_text(encoding="utf-8"))


def _replace_asset_digest(receipt: dict[str, object], name: str, digest: str) -> None:
    assets = receipt["assets"]
    assert isinstance(assets, dict)
    asset = assets[name]
    assert isinstance(asset, dict)
    artifact_id = asset["artifact_id"]
    asset["sha256"] = digest
    asset["content_uri"] = (
        f"https://artifacts.example.test/v1/artifacts/{artifact_id}/content/{digest}"
    )


@pytest.mark.parametrize(
    ("asset_name", "expected_error"),
    (
        (
            "operational_readiness",
            "PUBLISHED_OPERATIONAL_READINESS_DIGEST_MISMATCH",
        ),
        (
            "operational_readiness_validation",
            "PUBLISHED_OPERATIONAL_READINESS_VALIDATION_DIGEST_MISMATCH",
        ),
    ),
)
def test_release_evidence_rejects_unbound_operational_asset_bytes(
    tmp_path: Path,
    asset_name: str,
    expected_error: str,
) -> None:
    args = _readiness_arguments(tmp_path)
    receipt = _published_receipt(args)
    _replace_asset_digest(receipt, asset_name, f"sha256:{'9' * 64}")
    args.published_assets.write_text(json.dumps(receipt), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_error):
        build_evidence(args)


def test_release_evidence_points_to_published_operational_assets(tmp_path: Path) -> None:
    args = _readiness_arguments(tmp_path)
    receipt = _published_receipt(args)
    assets = receipt["assets"]
    assert isinstance(assets, dict)

    evidence = build_evidence(args)

    readiness_bytes = args.operational_readiness.read_bytes()
    validation_bytes = args.operational_readiness_validation.read_bytes()
    assert evidence["operational_readiness_uri"] == assets["operational_readiness"]["content_uri"]
    assert evidence["operational_readiness_sha256"] == (
        "sha256:" + hashlib.sha256(readiness_bytes).hexdigest()
    )
    assert (
        evidence["operational_readiness_validation_uri"]
        == (assets["operational_readiness_validation"]["content_uri"])
    )
    assert evidence["operational_readiness_validation_sha256"] == (
        "sha256:" + hashlib.sha256(validation_bytes).hexdigest()
    )
