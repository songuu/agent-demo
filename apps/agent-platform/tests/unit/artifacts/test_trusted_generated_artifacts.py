from __future__ import annotations

import copy
import hashlib
from typing import Any
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore
from agent_platform.infrastructure.artifacts.trusted_generated import (
    build_trusted_generated_json,
)


class StoredBody:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def read(self) -> bytes:
        return self._content


class RecordingS3Client:
    def __init__(self) -> None:
        self.puts: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> None:
        self.puts.append(kwargs)

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {
            "Contents": [{"Key": item["Key"]} for item in self.puts],
            "IsTruncated": False,
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        stored = next(item for item in self.puts if item["Key"] == kwargs["Key"])
        return {
            "Body": StoredBody(stored["Body"]),
            "ContentType": stored["ContentType"],
            "Metadata": stored["Metadata"],
        }


def store(client: RecordingS3Client) -> S3ArtifactStore:
    return S3ArtifactStore(
        client=client,
        bucket="artifact-bucket",
        kms_key_id=None,
        environment="test",
    )


def trusted_artifact(
    *,
    kind: str = "report",
    source: str = "deterministic_runtime",
    classification: str = "internal",
) -> ArtifactRecord:
    content, provenance = build_trusted_generated_json(
        {"schema_version": "1.0", "summary": "generated internally"},
        kind=kind,
        source=source,
    )
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind=kind,
        media_type="application/json",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification=classification,
        created_by="platform-runtime",
        scan_status="trusted_generated",
        scan_provenance=provenance,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "source"),
    (
        ("report", "deterministic_runtime"),
        ("tool_result", "tool_gateway"),
    ),
)
async def test_s3_accepts_only_allowlisted_canonical_platform_json(
    kind: str,
    source: str,
) -> None:
    client = RecordingS3Client()

    artifact = trusted_artifact(kind=kind, source=source)
    await store(client).put(artifact)

    assert len(client.puts) == 1
    metadata = client.puts[0]["Metadata"]
    assert metadata["scan-status"] == "trusted_generated"
    assert metadata["scan-evidence-type"] == "trusted-generated"
    assert metadata["trusted-source"] == source
    assert metadata["artifact-kind"] == kind
    assert metadata["sha256"] == artifact.sha256

    restored = await store(client).get(artifact.artifact_id, artifact.tenant_id)
    assert restored.content == artifact.content
    assert restored.scan_status == "trusted_generated"
    assert restored.scan_provenance == artifact.scan_provenance


@pytest.mark.asyncio
async def test_s3_rejects_forged_trusted_generated_hash_proof() -> None:
    client = RecordingS3Client()
    artifact = trusted_artifact()
    forged = copy.deepcopy(artifact.scan_provenance)
    forged["trusted_generated"]["sha256"] = "0" * 64
    artifact.scan_provenance = forged

    with pytest.raises(PlatformError, match="ARTIFACT_TRUSTED_GENERATED_BINDING_INVALID"):
        await store(client).put(artifact)

    assert client.puts == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "source"),
    (
        ("document", "deterministic_runtime"),
        ("report", "tool_gateway"),
        ("report", "unknown_runtime"),
    ),
)
async def test_s3_rejects_non_allowlisted_trusted_generated_kind_or_source(
    kind: str,
    source: str,
) -> None:
    client = RecordingS3Client()
    artifact = trusted_artifact()
    forged = copy.deepcopy(artifact.scan_provenance)
    forged["trusted_generated"]["kind"] = kind
    forged["trusted_generated"]["source"] = source
    artifact.kind = kind
    artifact.scan_provenance = forged

    with pytest.raises(PlatformError, match="ARTIFACT_TRUSTED_GENERATED_SOURCE_DENIED"):
        await store(client).put(artifact)

    assert client.puts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("scan_status", ("not_scanned", "structural_only", "unknown"))
async def test_s3_rejects_missing_unknown_or_non_clean_external_evidence(
    scan_status: str,
) -> None:
    client = RecordingS3Client()
    content = b"external upload"
    artifact = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by="external-user",
        scan_status=scan_status,
        scan_provenance={},
    )

    with pytest.raises(PlatformError, match="ARTIFACT_STORAGE_EVIDENCE_REQUIRED"):
        await store(client).put(artifact)

    assert client.puts == []


@pytest.mark.asyncio
async def test_s3_rejects_non_internal_trusted_generated_artifact() -> None:
    client = RecordingS3Client()

    with pytest.raises(PlatformError, match="ARTIFACT_TRUSTED_GENERATED_SOURCE_DENIED"):
        await store(client).put(trusted_artifact(classification="confidential"))

    assert client.puts == []


@pytest.mark.asyncio
async def test_s3_get_rejects_tampered_trusted_generated_metadata() -> None:
    client = RecordingS3Client()
    artifact = trusted_artifact()
    artifact_store = store(client)
    await artifact_store.put(artifact)
    client.puts[0]["Metadata"]["trusted-source"] = "forged_runtime"

    with pytest.raises(PlatformError, match="ARTIFACT_TRUSTED_GENERATED_SOURCE_DENIED"):
        await artifact_store.get(artifact.artifact_id, artifact.tenant_id)


def test_trusted_generated_builder_rejects_non_allowlisted_source() -> None:
    with pytest.raises(ValueError, match="TRUSTED_GENERATED_SOURCE_DENIED"):
        build_trusted_generated_json(
            {"unsafe": "claim"},
            kind="document",
            source="external_upload",
        )
