from __future__ import annotations

import json
from pathlib import Path

PLATFORM_ROOT = Path(__file__).parents[3]
REPOSITORY_ROOT = PLATFORM_ROOT.parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "agent-platform-release.yml"


def test_workflow_requires_external_multi_role_approval_bundle() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "AGENT_PLATFORM_RELEASE_APPROVALS_URI" in workflow
    assert "AGENT_PLATFORM_RELEASE_APPROVALS_BASE_URL" not in workflow
    assert "AGENT_PLATFORM_RELEASE_APPROVALS_BEARER_TOKEN" in workflow
    assert "AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY" in workflow
    assert "AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_ISSUER" in workflow
    assert "^https://.+/sha256:[0-9a-f]{64}$" in workflow
    assert '"${APPROVALS_URI}.sigstore.json"' in workflow
    assert "cosign verify-blob" in workflow
    assert '--bundle "${signature_bundle}"' in workflow
    assert '--certificate-identity "${APPROVALS_SIGNER_IDENTITY}"' in workflow
    assert '--certificate-oidc-issuer "${APPROVALS_SIGNER_ISSUER}"' in workflow
    assert 'claimed_digest="${APPROVALS_URI##*/}"' in workflow
    assert 'sha256sum "${approvals}"' in workflow
    assert "deploy/ci/validate_release_approvals.py" in workflow
    assert "--signature-bundle" in workflow
    assert '--source-uri "${APPROVALS_URI}"' in workflow
    assert "--expected-signer-identity" in workflow
    assert "--expected-signer-issuer" in workflow
    assert "--approvals-bundle" in workflow
    assert "--deployment-approval" in workflow
    assert "--approval-actor" not in workflow
    assert "--approval-role" not in workflow

    schema = json.loads(
        (PLATFORM_ROOT / "deploy" / "ci" / "release-approvals.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert schema["properties"]["schema_version"]["const"] == "1.1"
    assert set(schema["properties"]["signer"]["required"]) == {"identity", "issuer"}
    assert schema["properties"]["approvals"]["minItems"] == 4
    assert schema["properties"]["approvals"]["maxItems"] == 4
    role_values = schema["properties"]["approvals"]["items"]["properties"]["role"]["enum"]
    assert set(role_values) == {"security", "business", "sre", "data-system-owner"}
    authentication = schema["properties"]["approvals"]["items"]["properties"]["authentication"]
    assert authentication["properties"]["assurance"]["const"] == "phishing-resistant"


def test_release_documentation_names_real_external_prerequisites() -> None:
    documentation = (
        PLATFORM_ROOT / "docs" / "governance" / "production-release-workflow.md"
    ).read_text(encoding="utf-8")

    for marker in (
        "provider-specific progressive delivery controller",
        "禁止发起人自审",
        "Security",
        "Business",
        "SRE",
        "Data/System Owner",
        "WebAuthn/FIDO2/PIV",
        "exact SHA/digest",
        "不会创建虚假的集群、流量或审批证据",
        "human-review-evidence.schema.json",
        "candidate_manifest_sha256",
        "candidate_results_sha256",
        "50-100",
        "静态 secret 只用于审核服务认证",
        "AGENT_PLATFORM_RELEASE_APPROVALS_URI",
        "AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY",
        "canonical JSON",
        "Sigstore",
        "external-release-preflight.json",
        "AGENT_PLATFORM_PREFLIGHT_APP_CLIENT_ID",
        "AGENT_PLATFORM_PREFLIGHT_APP_PRIVATE_KEY",
        "只读 GitHub App",
        "Secret metadata",
        "main branch protection/ruleset",
        "agent-platform-v*",
        "Quality, policy, deployment, and offline eval gates",
        "integration_id=15368",
        "API-visible",
        "bypass_actors",
        "365 天",
    ):
        assert marker in documentation


def test_release_environment_example_names_signed_approval_inputs() -> None:
    environment = (PLATFORM_ROOT / ".env.example").read_text(encoding="utf-8")

    for marker in (
        "AGENT_PLATFORM_RELEASE_APPROVALS_URI=",
        "AGENT_PLATFORM_RELEASE_APPROVALS_BEARER_TOKEN=",
        "AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY=",
        "AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_ISSUER=",
    ):
        assert marker in environment
    assert "AGENT_PLATFORM_RELEASE_APPROVALS_BASE_URL" not in environment
