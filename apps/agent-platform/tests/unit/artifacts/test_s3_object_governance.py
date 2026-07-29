from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore


def _release_evidence(*, classification: str = "restricted") -> ArtifactRecord:
    content = b'{"schema_version":"ReleaseEvidence@1.0"}'
    digest = hashlib.sha256(content).hexdigest()
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-release",
        run_id=None,
        kind="release-evidence",
        media_type="application/json",
        content=content,
        sha256=digest,
        classification=classification,
        created_by="release-controller",
        scan_status="malware_clean",
        scan_provenance={
            "release_binding": {
                "release_id": "release-2026-07-27",
                "git_sha": "a" * 40,
                "image_digest": "sha256:" + "b" * 64,
            },
            "malware": {
                "request_id": "scan-request-release",
                "sha256": digest,
                "size_bytes": len(content),
                "verdict": "clean",
                "engine": "controlled-av",
                "engine_version": "1",
                "scanned_at": "2026-07-27T00:00:00+00:00",
                "evidence_id": "scan-evidence-release",
            },
        },
    )


@pytest.mark.asyncio
async def test_restricted_release_evidence_is_locked_on_final_key_for_at_least_365_days() -> None:
    client = _GovernedS3Client()
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-prod",
        staging_bucket="artifact-prod-staging",
        kms_key_id="kms-general",
        environment="prod",
    )

    artifact = await store.put(_release_evidence())

    request = client.put_requests[0]
    assert "/.pending/" not in request["Key"]
    assert request["ObjectLockMode"] == "COMPLIANCE"
    assert request["ObjectLockRetainUntilDate"] > datetime.now(UTC) + timedelta(
        days=364,
        hours=23,
    )
    assert artifact.object_version_id == "version-release"
    assert artifact.object_retain_until == request["ObjectLockRetainUntilDate"]
    assert artifact.retention_policy == "release-evidence@1:immutable:365d"
    assert request["Metadata"]["release-id"] == "release-2026-07-27"
    assert request["Metadata"]["release-git-sha"] == "a" * 40
    assert request["Metadata"]["release-image-digest"] == "sha256:" + "b" * 64


@pytest.mark.asyncio
async def test_release_evidence_fails_closed_without_restricted_classification() -> None:
    client = _GovernedS3Client()
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-prod",
        staging_bucket="artifact-prod-staging",
        kms_key_id="kms-general",
        environment="prod",
    )

    with pytest.raises(
        PlatformError,
        match="RELEASE_EVIDENCE_RESTRICTED_CLASSIFICATION_REQUIRED",
    ):
        await store.put(_release_evidence(classification="internal"))

    assert client.put_requests == []


class _GovernedS3Client:
    def __init__(self) -> None:
        self.put_requests: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> dict[str, str]:
        self.put_requests.append(kwargs)
        return {"VersionId": "version-release"}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        request = self.put_requests[-1]
        return {
            "ContentLength": len(request["Body"]),
            "Metadata": request["Metadata"],
            "VersionId": "version-release",
            "ObjectLockMode": request["ObjectLockMode"],
            "ObjectLockRetainUntilDate": request["ObjectLockRetainUntilDate"],
            "ServerSideEncryption": request["ServerSideEncryption"],
            "SSEKMSKeyId": request["SSEKMSKeyId"],
        }


@pytest.mark.asyncio
async def test_delete_targets_the_exact_object_version() -> None:
    artifact_id = uuid4()
    client = _DeleteS3Client(artifact_id=artifact_id, legal_hold=False)
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-test",
        kms_key_id=None,
        environment="test",
    )

    await store.delete(artifact_id, "tenant-a")

    assert client.deletes == [
        {
            "Bucket": "artifact-test",
            "Key": client.key,
            "VersionId": "version-delete",
        }
    ]


@pytest.mark.asyncio
async def test_delete_fails_closed_for_object_store_legal_hold() -> None:
    artifact_id = uuid4()
    client = _DeleteS3Client(artifact_id=artifact_id, legal_hold=True)
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-test",
        kms_key_id=None,
        environment="test",
    )

    with pytest.raises(PlatformError, match="ARTIFACT_LEGAL_HOLD_ACTIVE"):
        await store.delete(artifact_id, "tenant-a")

    assert client.deletes == []


class _DeleteS3Client:
    def __init__(self, *, artifact_id: Any, legal_hold: bool) -> None:
        self.key = f"test/tenant/tenant-a/run/unbound/artifacts/{artifact_id}"
        self.legal_hold = legal_hold
        self.deletes: list[dict[str, Any]] = []

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "Contents": [{"Key": self.key}],
            "IsTruncated": False,
        }

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "VersionId": "version-delete",
            "ObjectLockLegalHoldStatus": "ON" if self.legal_hold else "OFF",
        }

    def delete_object(self, **kwargs: Any) -> None:
        self.deletes.append(kwargs)
