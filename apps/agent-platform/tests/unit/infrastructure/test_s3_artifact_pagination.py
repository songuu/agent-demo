from __future__ import annotations

from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore


class _PagedS3Client:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self._pages = pages
        self.calls: list[dict[str, object]] = []

    def list_objects_v2(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return self._pages[len(self.calls) - 1]


@pytest.mark.asyncio
async def test_artifact_lookup_follows_s3_continuation_tokens() -> None:
    artifact_id = uuid4()
    target = f"prod/tenant/tenant-a/run/run-2/artifacts/{artifact_id}"
    client = _PagedS3Client(
        [
            {
                "Contents": [{"Key": (f"prod/tenant/tenant-a/run/run-1/artifacts/{uuid4()}")}],
                "IsTruncated": True,
                "NextContinuationToken": "page-2",
            },
            {
                "Contents": [{"Key": target}],
                "IsTruncated": False,
            },
        ]
    )
    store = S3ArtifactStore(
        client=client,
        bucket="artifacts",
        kms_key_id=None,
        environment="prod",
    )

    key = await store._find_key(artifact_id, "tenant-a")

    assert key == target
    assert client.calls == [
        {
            "Bucket": "artifacts",
            "Prefix": "prod/tenant/tenant-a/",
            "MaxKeys": 1_000,
        },
        {
            "Bucket": "artifacts",
            "Prefix": "prod/tenant/tenant-a/",
            "MaxKeys": 1_000,
            "ContinuationToken": "page-2",
        },
    ]


@pytest.mark.asyncio
async def test_artifact_lookup_rejects_missing_or_replayed_continuation_token() -> None:
    for token in (None, "same-token"):
        pages: list[dict[str, object]] = [
            {
                "Contents": [],
                "IsTruncated": True,
                "NextContinuationToken": token,
            }
        ]
        if token is not None:
            pages.append(
                {
                    "Contents": [],
                    "IsTruncated": True,
                    "NextContinuationToken": token,
                }
            )
        store = S3ArtifactStore(
            client=_PagedS3Client(pages),
            bucket="artifacts",
            kms_key_id=None,
            environment="prod",
        )

        with pytest.raises(
            PlatformError,
            match="ARTIFACT_LISTING_PAGINATION_INVALID",
        ):
            await store._find_key(uuid4(), "tenant-a")
