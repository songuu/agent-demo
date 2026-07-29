from __future__ import annotations

from typing import Any

import pytest

from agent_platform.infrastructure.dependency_health import s3_probe


class GovernedBucketClient:
    def __init__(self) -> None:
        self.versioning: dict[str, Any] = {"Status": "Enabled"}
        self.encryption: dict[str, Any] = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "kms-general",
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            }
        }
        self.lifecycle: dict[str, Any] = {
            "Rules": [{"ID": "artifact-retention", "Status": "Enabled"}]
        }
        self.public_access: dict[str, Any] = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        self.object_lock: dict[str, Any] = {
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "COMPLIANCE",
                        "Days": 365,
                    }
                },
            }
        }
        self.calls: list[str] = []

    def head_bucket(self, *, Bucket: str) -> None:
        assert Bucket in {"artifact-prod", "artifact-staging"}
        self.calls.append("head")

    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append("versioning")
        return self.versioning

    def get_bucket_encryption(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append("encryption")
        return self.encryption

    def get_bucket_lifecycle_configuration(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append("lifecycle")
        return self.lifecycle

    def get_public_access_block(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append("public_access")
        return self.public_access

    def get_object_lock_configuration(self, *, Bucket: str) -> dict[str, Any]:
        self.calls.append("object_lock")
        return self.object_lock


@pytest.mark.asyncio
async def test_s3_governance_probe_reads_back_every_required_control() -> None:
    client = GovernedBucketClient()

    await s3_probe(
        client,
        "artifact-prod",
        require_governance=True,
        expected_kms_key="kms-general",
    )()

    assert client.calls == [
        "head",
        "versioning",
        "encryption",
        "lifecycle",
        "public_access",
        "object_lock",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "error_code"),
    [
        (lambda client: setattr(client, "versioning", {}), "S3_VERSIONING_REQUIRED"),
        (
            lambda client: setattr(
                client,
                "encryption",
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    }
                },
            ),
            "S3_KMS_ENCRYPTION_REQUIRED",
        ),
        (
            lambda client: setattr(
                client,
                "lifecycle",
                {"Rules": [{"ID": "disabled", "Status": "Disabled"}]},
            ),
            "S3_LIFECYCLE_REQUIRED",
        ),
        (
            lambda client: client.public_access["PublicAccessBlockConfiguration"].update(
                {"RestrictPublicBuckets": False}
            ),
            "S3_PUBLIC_ACCESS_BLOCK_REQUIRED",
        ),
        (
            lambda client: setattr(
                client,
                "object_lock",
                {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}},
            ),
            "S3_OBJECT_LOCK_REQUIRED",
        ),
    ],
)
async def test_s3_governance_probe_fails_closed_for_missing_control(
    mutate: Any,
    error_code: str,
) -> None:
    client = GovernedBucketClient()
    mutate(client)

    with pytest.raises(RuntimeError, match=error_code):
        await s3_probe(
            client,
            "artifact-prod",
            require_governance=True,
            expected_kms_key="kms-general",
        )()


@pytest.mark.asyncio
async def test_s3_governance_probe_accepts_per_object_retention_without_bucket_default() -> None:
    client = GovernedBucketClient()
    client.object_lock = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    await s3_probe(
        client,
        "artifact-prod",
        require_governance=True,
        expected_kms_key="kms-general",
    )()


@pytest.mark.asyncio
async def test_s3_basic_probe_does_not_require_cloud_governance_in_local_tests() -> None:
    client = GovernedBucketClient()

    await s3_probe(client, "artifact-prod")()

    assert client.calls == ["head"]


@pytest.mark.asyncio
async def test_s3_staging_probe_requires_private_kms_short_lived_unlocked_bucket() -> None:
    client = GovernedBucketClient()
    client.lifecycle = {
        "Rules": [
            {
                "ID": "multipart-staging-cleanup",
                "Status": "Enabled",
                "Expiration": {"Days": 1},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
            }
        ]
    }
    client.object_lock = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}}

    await s3_probe(
        client,
        "artifact-staging",
        require_staging_controls=True,
        expected_kms_key="kms-general",
    )()

    assert client.calls == [
        "head",
        "versioning",
        "encryption",
        "lifecycle",
        "public_access",
        "object_lock",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("expiration_days", "object_lock_enabled", "error_code"),
    [
        (3, "Disabled", "S3_STAGING_SHORT_LIFECYCLE_REQUIRED"),
        (1, "Enabled", "S3_STAGING_OBJECT_LOCK_FORBIDDEN"),
    ],
)
async def test_s3_staging_probe_fails_closed_for_long_lived_or_locked_temp_objects(
    expiration_days: int,
    object_lock_enabled: str,
    error_code: str,
) -> None:
    client = GovernedBucketClient()
    client.lifecycle = {
        "Rules": [
            {
                "ID": "multipart-staging-cleanup",
                "Status": "Enabled",
                "Expiration": {"Days": expiration_days},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
                "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
            }
        ]
    }
    client.object_lock = {"ObjectLockConfiguration": {"ObjectLockEnabled": object_lock_enabled}}

    with pytest.raises(RuntimeError, match=error_code):
        await s3_probe(
            client,
            "artifact-staging",
            require_staging_controls=True,
            expected_kms_key="kms-general",
        )()
