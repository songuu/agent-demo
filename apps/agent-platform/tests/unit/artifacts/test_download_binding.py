from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from agent_platform.api.routes_artifacts import _validate_issued_download
from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactDownload, ArtifactRecord


def artifact() -> ArtifactRecord:
    content = b"evidence"
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        classification="internal",
        created_by="user-a",
    )


@pytest.mark.parametrize(
    ("url", "artifact_matches", "expires_delta"),
    [
        ("http://objects.example.test/file?signed=1", True, timedelta(seconds=60)),
        ("https://user:secret@objects.example.test/file", True, timedelta(seconds=60)),
        ("https://objects.example.test/file?signed=1", False, timedelta(seconds=60)),
        ("https://objects.example.test/file?signed=1", True, timedelta(seconds=-1)),
        ("https://objects.example.test/file?signed=1", True, timedelta(seconds=120)),
    ],
)
def test_download_binding_fails_closed(
    url: str,
    artifact_matches: bool,
    expires_delta: timedelta,
) -> None:
    stored = artifact()
    issued = ArtifactDownload(
        artifact_id=stored.artifact_id if artifact_matches else uuid4(),
        url=url,
        expires_at=datetime.now(UTC) + expires_delta,
    )

    with pytest.raises(PlatformError) as caught:
        _validate_issued_download(issued, stored, ttl_seconds=60)

    assert caught.value.code == "ARTIFACT_DOWNLOAD_BINDING_INVALID"
    assert caught.value.http_status == 503
