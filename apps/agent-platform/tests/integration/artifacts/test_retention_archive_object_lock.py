from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config  # type: ignore[import-untyped]

from agent_platform.infrastructure.retention_lifecycle import (
    ArchiveDescriptor,
    RetentionPolicy,
    S3ImmutableArchiveAdapter,
)

pytestmark = pytest.mark.integration


class _LocalMinioArchiveClient:
    """Preserve the requested SSE contract around local MinIO's absent KMS backend."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.requested_encryption: list[str] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        encryption = kwargs.pop("ServerSideEncryption", None)
        if isinstance(encryption, str):
            self.requested_encryption.append(encryption)
        return self.delegate.put_object(**kwargs)

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        response = self.delegate.head_object(**kwargs)
        response["ServerSideEncryption"] = "AES256"
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self.delegate, name)


def _client() -> Any:
    endpoint = os.getenv("AGENT_TEST_MINIO_URL", "").strip()
    access_key = os.getenv("AGENT_TEST_MINIO_ACCESS_KEY", "").strip()
    secret_key = os.getenv("AGENT_TEST_MINIO_SECRET_KEY", "").strip()
    if not endpoint or not access_key or not secret_key:
        pytest.skip("MinIO integration credentials are required")
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


@pytest.mark.asyncio
async def test_real_minio_archive_is_versioned_locked_and_restorable() -> None:
    s3 = _client()
    bucket = f"retention-lock-{uuid4().hex[:16]}"
    await asyncio.to_thread(
        s3.create_bucket,
        Bucket=bucket,
        ObjectLockEnabledForBucket=True,
    )
    wrapped = _LocalMinioArchiveClient(s3)
    adapter = S3ImmutableArchiveAdapter(
        client=wrapped,
        bucket=bucket,
        environment="integration",
        kms_key_id=None,
        object_lock_mode="GOVERNANCE",
    )
    policy = RetentionPolicy(
        policy_key="agent-run-integration",
        version=1,
        resource_type="agent_run",
        classification="internal",
        business_requirement="Integration restore proof.",
        audit_requirement="Version and Object Lock readback.",
        owner_id="platform-data-governance",
        online_retention_days=180,
        archive_retention_days=365,
        disposition="archive_then_purge",
        immutable_archive=True,
        legal_hold_enabled=True,
    )
    try:
        receipt = await adapter.archive_json_lines(
            ArchiveDescriptor(
                tenant_id="tenant-integration",
                resource_type="agent_run",
                resource_id="run-integration",
                policy=policy,
            ),
            [{"record_type": "agent_run", "status": "completed"}],
        )

        retention = await asyncio.to_thread(
            s3.get_object_retention,
            Bucket=bucket,
            Key=receipt.uri.split(f"s3://{bucket}/", 1)[1],
            VersionId=receipt.version_id,
        )
        restored = await adapter.restore_and_verify(receipt)

        assert receipt.version_id
        assert receipt.retain_until > datetime.now(UTC)
        assert retention["Retention"]["Mode"] == "GOVERNANCE"
        assert retention["Retention"]["RetainUntilDate"] >= receipt.retain_until
        assert wrapped.requested_encryption == ["AES256"]
        assert b'"status":"completed"' in restored
    finally:
        try:
            versions = await asyncio.to_thread(s3.list_object_versions, Bucket=bucket)
            for item in [
                *versions.get("Versions", []),
                *versions.get("DeleteMarkers", []),
            ]:
                await asyncio.to_thread(
                    s3.delete_object,
                    Bucket=bucket,
                    Key=item["Key"],
                    VersionId=item["VersionId"],
                    BypassGovernanceRetention=True,
                )
            await asyncio.to_thread(s3.delete_bucket, Bucket=bucket)
        finally:
            s3.close()
