from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from deploy.ci.validate_foundation_attestation import validate_foundation_attestation

PLATFORM_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PLATFORM_ROOT / "deploy" / "ci" / "foundation-attestation.schema.json"
RELEASE_ID = "release-2026-07-27"
GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
PLAN_DIGEST = "sha256:" + "c" * 64
READBACK_DIGEST = "sha256:" + "d" * 64
EXECUTION_DIGEST = "sha256:" + "e" * 64
SIGNER_IDENTITY = (
    "https://github.com/example/platform/.github/workflows/foundation.yml@refs/heads/main"
)
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"


def _digest_uri(digest: str) -> str:
    return f"https://evidence.example.test/immutable/{digest}"


def foundation_attestation(
    *,
    now: datetime | None = None,
    execution_mode: str = "terraform-apply-readback",
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    binding = {
        "release_id": RELEASE_ID,
        "git_sha": GIT_SHA,
        "image_digest": IMAGE_DIGEST,
    }
    execution: dict[str, Any] = {
        "mode": execution_mode,
        "completed_at": (current - timedelta(minutes=15)).isoformat(),
        "evidence_sha256": EXECUTION_DIGEST,
        "evidence_uri": _digest_uri(EXECUTION_DIGEST),
        "resource_readback_sha256": READBACK_DIGEST,
        "resource_readback_uri": _digest_uri(READBACK_DIGEST),
        "tool": "terraform",
        "tool_version": "1.9.8",
    }
    if execution_mode == "terraform-apply-readback":
        execution.update(
            {
                "read_only": False,
                "apply_id": "apply-prod-20260727-001",
                "apply_status": "applied",
                "applied_plan_sha256": PLAN_DIGEST,
            }
        )
    else:
        execution.update(
            {
                "read_only": True,
                "query_set_id": "aws-config-prod-foundation-v3",
                "tool": "aws-config",
                "tool_version": "1.0",
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "production-foundation-attestation",
        "environment": "prod",
        **binding,
        "terraform": {
            "version": "1.9.8",
            "plan_id": "plan-prod-20260727-001",
            "plan_sha256": PLAN_DIGEST,
            "plan_uri": _digest_uri(PLAN_DIGEST),
            "module_source": ("git::https://github.com/example/platform-foundation.git?ref=v3.2.1"),
            "module_version": "3.2.1",
            "generated_at": (current - timedelta(minutes=45)).isoformat(),
        },
        "execution": execution,
        "provider": {
            "name": "aws",
            "account_resource_id": (
                "arn:aws:organizations::123456789012:account/o-prod/123456789012"
            ),
            "regions": ["us-east-1", "us-west-2"],
        },
        "resources": {
            "kubernetes": {
                "resource_id": ("arn:aws:eks:us-east-1:123456789012:cluster/agent-platform-prod"),
                "region": "us-east-1",
                "private_endpoint": True,
                "multi_zone": True,
                "workload_identity_enabled": True,
            },
            "postgres": {
                "resource_id": ("arn:aws:rds:us-east-1:123456789012:cluster:agent-platform-prod"),
                "region": "us-east-1",
                "managed": True,
                "high_availability": True,
                "multi_zone": True,
                "pitr_enabled": True,
                "backup_retention_days": 35,
                "rpo_minutes": 5,
                "rto_minutes": 30,
                "tls_required": True,
                "kms_key_id": (
                    "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
                ),
                "restore_test_evidence_sha256": "sha256:" + "1" * 64,
                "restore_test_evidence_uri": _digest_uri("sha256:" + "1" * 64),
                "restore_tested_at": (current - timedelta(days=2)).isoformat(),
            },
            "artifact_storage": {
                "final": {
                    "resource_id": "arn:aws:s3:::agent-platform-prod-final",
                    "region": "us-east-1",
                    "kms_key_id": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "22222222-2222-4222-8222-222222222222"
                    ),
                    "versioning_enabled": True,
                    "object_lock_enabled": True,
                    "object_lock_mode": "COMPLIANCE",
                    "minimum_retention_days": 365,
                    "public_access_blocked": True,
                    "tls_only": True,
                },
                "staging": {
                    "resource_id": "arn:aws:s3:::agent-platform-prod-staging",
                    "region": "us-east-1",
                    "kms_key_id": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "33333333-3333-4333-8333-333333333333"
                    ),
                    "versioning_enabled": True,
                    "object_lock_enabled": False,
                    "public_access_blocked": True,
                    "tls_only": True,
                    "abort_incomplete_multipart_days": 1,
                },
            },
            "temporal": {
                "resource_id": ("temporal://cloud/accounts/prod/namespaces/agent-platform-prod"),
                "regions": ["us-east-1", "us-west-2"],
                "namespace": "agent-platform-prod",
                "tls_enabled": True,
                "managed_or_highly_available": True,
                "namespace_isolated": True,
                "history_archival_enabled": True,
                "worker_versioning_enabled": True,
            },
            "opa": {
                "resource_id": (
                    "k8s://arn:aws:eks:us-east-1:123456789012:"
                    "cluster/agent-platform-prod/namespaces/agent-platform-prod/services/opa"
                ),
                "tls_enabled": True,
                "fail_closed": True,
                "bundle_digest": "sha256:" + "2" * 64,
                "bundle_uri": _digest_uri("sha256:" + "2" * 64),
                "bundle_signature_verified": True,
            },
            "egress": {
                "policy_resource_id": (
                    "arn:aws:network-firewall:us-east-1:123456789012:"
                    "firewall-policy/agent-platform-prod"
                ),
                "default_deny": True,
                "metadata_service_denied": True,
                "kubernetes_api_denied": True,
                "proxy_resource_ids": {
                    name: (
                        "arn:aws:elasticloadbalancing:us-east-1:123456789012:"
                        f"loadbalancer/net/{name}/1234567890abcdef"
                    )
                    for name in (
                        "agent",
                        "artifact-scan",
                        "commit",
                        "control",
                        "delivery",
                        "quota-redis",
                        "retention",
                    )
                },
            },
            "secrets": {
                "manager_resource_id": (
                    "arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-platform-prod"
                ),
                "region": "us-east-1",
                "rotation_enabled": True,
                "access_audit_enabled": True,
                "jit_admin_enabled": True,
                "workload_identity_resource_ids": {
                    name: (f"arn:aws:iam::123456789012:role/agent-platform-prod-{name}")
                    for name in (
                        "agent-worker",
                        "api",
                        "commit-worker",
                        "migration",
                        "outbox",
                        "retention",
                    )
                },
                "secret_resource_ids": {
                    name: (
                        "arn:aws:secretsmanager:us-east-1:123456789012:"
                        f"secret:agent-platform-prod-{name}"
                    )
                    for name in (
                        "action-payload-encryption",
                        "agent-broker",
                        "commit-broker",
                        "database-api",
                        "database-commit",
                        "database-management",
                        "database-migration",
                        "database-outbox",
                        "database-retention",
                        "database-worker",
                        "memory-encryption",
                        "openai",
                        "quota-redis",
                        "webhook-signing",
                    )
                },
                "kms_key_resource_ids": {
                    "action-payload": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "44444444-4444-4444-8444-444444444444"
                    ),
                    "artifact": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "55555555-5555-4555-8555-555555555555"
                    ),
                    "memory": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "66666666-6666-4666-8666-666666666666"
                    ),
                    "release-evidence": (
                        "arn:aws:kms:us-east-1:123456789012:key/"
                        "77777777-7777-4777-8777-777777777777"
                    ),
                },
            },
        },
        "approvals": [
            {
                **binding,
                "actor": "infra-owner@example.test",
                "role": "infrastructure-owner",
                "decision": "approved",
                "approved_at": (current - timedelta(minutes=10)).isoformat(),
                "evidence_uri": _digest_uri("sha256:" + "3" * 64),
            },
            {
                **binding,
                "actor": "security@example.test",
                "role": "security",
                "decision": "approved",
                "approved_at": (current - timedelta(minutes=8)).isoformat(),
                "evidence_uri": _digest_uri("sha256:" + "4" * 64),
            },
        ],
        "signer": {
            "identity": SIGNER_IDENTITY,
            "issuer": SIGNER_ISSUER,
        },
        "attested_at": current.isoformat(),
    }


def _validated(
    evidence: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    source_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_foundation_attestation(
        evidence,
        schema,
        source_bytes=payload,
        source_uri=_digest_uri(source_digest),
        expected_release_id=RELEASE_ID,
        expected_git_sha=GIT_SHA,
        expected_image_digest=IMAGE_DIGEST,
        expected_terraform_version="1.9.8",
        expected_signer_identity=SIGNER_IDENTITY,
        expected_signer_issuer=SIGNER_ISSUER,
        maximum_age_seconds=86400,
        now=now,
    )


@pytest.mark.parametrize("execution_mode", ["terraform-apply-readback", "cloud-api-read-only"])
def test_accepts_real_apply_or_read_only_cloud_resource_attestation(
    execution_mode: str,
) -> None:
    evidence = foundation_attestation(execution_mode=execution_mode)

    report = _validated(evidence)

    assert report["validated"] is True
    assert report["execution_mode"] == execution_mode
    assert report["terraform_version"] == "1.9.8"
    assert report["resource_ids"]["postgres"].startswith("arn:aws:rds:")
    assert report["approved_by"] == [
        "infra-owner@example.test",
        "security@example.test",
    ]


@pytest.mark.parametrize(
    ("path", "value", "error"),
    [
        (("git_sha",), "f" * 40, "FOUNDATION_ATTESTATION_GIT_SHA_MISMATCH"),
        (("terraform", "version"), "1.10.0", "FOUNDATION_ATTESTATION_SCHEMA_INVALID"),
        (
            ("execution", "tool_version"),
            "1.10.0",
            "FOUNDATION_ATTESTATION_EXECUTION_TERRAFORM_VERSION_MISMATCH",
        ),
        (
            ("resources", "postgres", "pitr_enabled"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "artifact_storage", "final", "object_lock_enabled"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "temporal", "tls_enabled"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "opa", "fail_closed"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "egress", "default_deny"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "secrets", "rotation_enabled"),
            False,
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
        (
            ("resources", "postgres", "resource_id"),
            "resource://postgres-prod",
            "FOUNDATION_ATTESTATION_SCHEMA_INVALID",
        ),
    ],
)
def test_rejects_identity_or_critical_cloud_control_mismatch(
    path: tuple[str, ...],
    value: object,
    error: str,
) -> None:
    evidence = foundation_attestation()
    target: dict[str, Any] = evidence
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(ValueError, match=error):
        _validated(evidence)


def test_rejects_non_content_addressed_source_or_execution_evidence() -> None:
    evidence = foundation_attestation()
    payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="FOUNDATION_ATTESTATION_SOURCE_URI_DIGEST_MISMATCH"):
        validate_foundation_attestation(
            evidence,
            schema,
            source_bytes=payload,
            source_uri=_digest_uri("sha256:" + "0" * 64),
            expected_release_id=RELEASE_ID,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            expected_terraform_version="1.9.8",
            expected_signer_identity=SIGNER_IDENTITY,
            expected_signer_issuer=SIGNER_ISSUER,
            maximum_age_seconds=86400,
        )

    evidence["execution"]["resource_readback_uri"] = _digest_uri("sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="FOUNDATION_ATTESTATION_READBACK_DIGEST_URI_MISMATCH"):
        _validated(evidence)


def test_rejects_stale_or_non_independent_approval() -> None:
    current = datetime.now(UTC)
    stale = foundation_attestation(now=current - timedelta(days=2))
    with pytest.raises(ValueError, match="FOUNDATION_ATTESTATION_EXPIRED"):
        _validated(stale, now=current)

    duplicated = foundation_attestation(now=current)
    duplicated["approvals"][1] = deepcopy(duplicated["approvals"][0])
    with pytest.raises(ValueError, match="FOUNDATION_ATTESTATION_APPROVERS_NOT_UNIQUE"):
        _validated(duplicated, now=current)
