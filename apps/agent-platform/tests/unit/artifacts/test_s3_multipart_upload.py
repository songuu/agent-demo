from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore

_MIB = 1024 * 1024


def _write_payload(path: Path, size_bytes: int) -> str:
    digest = hashlib.sha256()
    remaining = size_bytes
    block = b"a" * (64 * 1024)
    with path.open("wb") as handle:
        while remaining:
            chunk = block[: min(len(block), remaining)]
            handle.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _artifact(*, size_bytes: int, sha256: str) -> ArtifactRecord:
    return ArtifactRecord(
        artifact_id=__import__("uuid").uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="application/pdf",
        content=b"",
        size_bytes=size_bytes,
        sha256=sha256,
        classification="internal",
        created_by="user-1",
        scan_status="malware_clean",
        scan_provenance={
            "malware": {
                "request_id": "scan-request-1",
                "sha256": sha256,
                "size_bytes": size_bytes,
                "verdict": "clean",
                "engine": "controlled-av",
                "engine_version": "1",
                "scanned_at": "2026-07-24T00:00:00+00:00",
                "evidence_id": "scan-evidence-1",
            }
        },
    )


@pytest.mark.asyncio
async def test_large_file_uses_bounded_multipart_temp_object_and_final_verification(
    tmp_path: Path,
) -> None:
    size_bytes = 11 * _MIB + 17
    path = tmp_path / "upload.bin"
    sha256 = _write_payload(path, size_bytes)
    artifact = _artifact(size_bytes=size_bytes, sha256=sha256)
    client = _MultipartClient(size_bytes=size_bytes, sha256=sha256)
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-bucket",
        staging_bucket="artifact-staging",
        kms_key_id="kms-key",
        environment="prod",
        multipart_part_size_bytes=5 * _MIB,
    )

    stored = await store.put_file(artifact, path)

    assert stored is artifact
    assert client.put_object_calls == 0
    assert client.upload_sizes == [5 * _MIB, 5 * _MIB, _MIB + 17]
    assert max(client.upload_sizes) <= 5 * _MIB
    assert client.complete_calls == 1
    assert client.copy_calls == 1
    assert client.head_calls == 2
    assert client.abort_calls == 0
    assert client.deleted_objects[0][0] == "artifact-staging"
    assert "/.pending/" in client.deleted_objects[0][1]
    assert client.copy_source_bucket == "artifact-staging"
    assert stored.object_version_id == "version-final"
    assert stored.object_retain_until is not None
    assert stored.object_retain_until > datetime.now(UTC)
    assert not client.copied_from.endswith(f"/artifacts/{artifact.artifact_id}")


@pytest.mark.asyncio
async def test_multipart_failure_aborts_upload_and_never_publishes_final_object(
    tmp_path: Path,
) -> None:
    size_bytes = 7 * _MIB
    path = tmp_path / "upload.bin"
    sha256 = _write_payload(path, size_bytes)
    artifact = _artifact(size_bytes=size_bytes, sha256=sha256)
    client = _MultipartClient(size_bytes=size_bytes, sha256=sha256, fail_part=2)
    store = S3ArtifactStore(
        client=client,
        bucket="artifact-bucket",
        staging_bucket="artifact-staging",
        kms_key_id=None,
        environment="prod",
        multipart_part_size_bytes=5 * _MIB,
    )

    with pytest.raises(RuntimeError, match="injected multipart failure"):
        await store.put_file(artifact, path)

    assert client.abort_calls == 1
    assert client.complete_calls == 0
    assert client.copy_calls == 0
    assert client.final_keys == []


class _MultipartClient:
    def __init__(
        self,
        *,
        size_bytes: int,
        sha256: str,
        fail_part: int | None = None,
    ) -> None:
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.fail_part = fail_part
        self.upload_sizes: list[int] = []
        self.deleted_objects: list[tuple[str, str]] = []
        self.final_keys: list[str] = []
        self.copied_from = ""
        self.copy_source_bucket = ""
        self._final_head: dict[str, Any] | None = None
        self.complete_calls = 0
        self.copy_calls = 0
        self.head_calls = 0
        self.abort_calls = 0
        self.put_object_calls = 0
        self._metadata: dict[str, str] = {}

    def put_object(self, **kwargs: Any) -> None:
        self.put_object_calls += 1
        raise AssertionError("large file must not use put_object")

    def create_multipart_upload(self, **kwargs: Any) -> dict[str, str]:
        key = str(kwargs["Key"])
        assert "/.pending/" in key
        self._metadata = dict(kwargs["Metadata"])
        return {"UploadId": "upload-1"}

    def upload_part(self, **kwargs: Any) -> dict[str, str]:
        part_number = int(kwargs["PartNumber"])
        if part_number == self.fail_part:
            raise RuntimeError("injected multipart failure")
        body = bytes(kwargs["Body"])
        self.upload_sizes.append(len(body))
        return {"ETag": f"etag-{part_number}"}

    def complete_multipart_upload(self, **kwargs: Any) -> None:
        self.complete_calls += 1

    def abort_multipart_upload(self, **kwargs: Any) -> None:
        self.abort_calls += 1

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.head_calls += 1
        if kwargs["Bucket"] == "artifact-staging":
            return {
                "ContentLength": self.size_bytes,
                "Metadata": dict(self._metadata),
            }
        assert self._final_head is not None
        return dict(self._final_head)

    def copy_object(self, **kwargs: Any) -> dict[str, str]:
        self.copy_calls += 1
        self.copy_source_bucket = str(kwargs["CopySource"]["Bucket"])
        self.copied_from = str(kwargs["CopySource"]["Key"])
        self.final_keys.append(str(kwargs["Key"]))
        self._final_head = {
            "ContentLength": self.size_bytes,
            "Metadata": dict(self._metadata),
            "VersionId": "version-final",
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
            "ServerSideEncryption": kwargs["ServerSideEncryption"],
            "SSEKMSKeyId": kwargs["SSEKMSKeyId"],
        }
        return {"VersionId": "version-final"}

    def delete_object(self, **kwargs: Any) -> None:
        self.deleted_objects.append((str(kwargs["Bucket"]), str(kwargs["Key"])))
