from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"


def _production() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    return workflow["jobs"]["production"]


def _step(name: str) -> dict[str, Any]:
    for step in _production()["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"workflow step not found: {name}")


def test_production_fails_closed_on_signed_foundation_attestation_before_helm() -> None:
    production = _production()
    materialize = _step("Materialize short-lived production inputs")["run"]
    foundation = _step("Fetch, verify, and validate production foundation")
    validation = foundation["run"]
    names = [step.get("name") for step in production["steps"]]

    public_inputs = {
        "FOUNDATION_ATTESTATION_URI": ("${{ vars.AGENT_PLATFORM_FOUNDATION_ATTESTATION_URI }}"),
        "FOUNDATION_ATTESTATION_SIGNER_IDENTITY": (
            "${{ vars.AGENT_PLATFORM_FOUNDATION_ATTESTATION_SIGNER_IDENTITY }}"
        ),
        "FOUNDATION_ATTESTATION_SIGNER_ISSUER": (
            "${{ vars.AGENT_PLATFORM_FOUNDATION_ATTESTATION_SIGNER_ISSUER }}"
        ),
    }
    for name, value in public_inputs.items():
        assert name in materialize
        assert production["env"][name] == value
    assert "FOUNDATION_ATTESTATION_BEARER_TOKEN" not in materialize
    assert "FOUNDATION_ATTESTATION_BEARER_TOKEN" not in production["env"]
    assert foundation["env"]["FOUNDATION_ATTESTATION_BEARER_TOKEN"] == (
        "${{ secrets.AGENT_PLATFORM_FOUNDATION_ATTESTATION_BEARER_TOKEN }}"
    )
    assert (
        ': "${FOUNDATION_ATTESTATION_BEARER_TOKEN:'
        '?FOUNDATION_ATTESTATION_BEARER_TOKEN is required}"'
    ) in validation
    assert names.index("Fetch, verify, and validate production foundation") < names.index(
        "Deploy the same immutable digest to production"
    )
    assert "curl --fail --silent --show-error --proto '=https' --tlsv1.2" in validation
    assert "foundation-attestation.json.sigstore.json" in validation
    assert "validate_foundation_attestation.py" in validation
    assert '--expected-release-id "${RELEASE_ID}"' in validation
    assert '--expected-git-sha "${GITHUB_SHA}"' in validation
    assert '--expected-image-digest "${IMAGE_DIGEST}"' in validation
    assert '--expected-terraform-version "${TERRAFORM_VERSION}"' in validation
    assert "--signature-bundle" in validation
    assert "--source-uri" in validation


def test_foundation_attestation_and_validation_are_governed_release_assets() -> None:
    component = _step("Publish and read back governed component evidence")["run"]
    build = _step("Build complete release evidence")["run"]

    assert (
        "--asset foundation_attestation=../../.artifacts/production/foundation-attestation.json"
    ) in component
    assert (
        "--asset foundation_attestation_signature_bundle="
        "../../.artifacts/production/foundation-attestation.json.sigstore.json"
    ) in component
    assert (
        "--asset foundation_attestation_validation="
        "../../.artifacts/production/foundation-attestation-validation.json"
    ) in component
    assert "--readback-dir" in component
    assert "foundation_attestation_signature_bundle" in component
    assert '"${component_readback}/foundation_attestation"' in component
    assert (
        "--foundation-attestation-validation "
        "../../.artifacts/production/foundation-attestation-validation.json"
    ) in build
