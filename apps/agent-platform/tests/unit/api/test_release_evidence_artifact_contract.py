from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from agent_platform.api.dependencies import RequestIdentity
from agent_platform.api.routes_artifacts import (
    _artifact_record,
    _release_evidence_binding,
)
from agent_platform.application.errors import Forbidden, PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.config import Settings
from agent_platform.domain.enums import DataClassification
from agent_platform.domain.models import DataScope, Principal
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore

RELEASE_ID = "release-2026-07-27"
GIT_SHA = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
BINDING = {
    "release_id": RELEASE_ID,
    "git_sha": GIT_SHA,
    "image_digest": IMAGE_DIGEST,
}


def _identity(*, evidence_scope: bool = True) -> RequestIdentity:
    scopes = {"artifact:write"}
    if evidence_scope:
        scopes.add("artifact:evidence:write")
    return RequestIdentity(
        principal=Principal(
            user_id="release-publisher",
            tenant_id="tenant-a",
            roles=frozenset(),
            scopes=frozenset(scopes),
            auth_strength="phishing_resistant",
        ),
        data_scope=DataScope(
            tenant_id="tenant-a",
            resource_types=frozenset({"artifact"}),
            classifications=frozenset({DataClassification.RESTRICTED}),
        ),
    )


def _binding(
    settings: Settings,
    *,
    identity: RequestIdentity | None = None,
    classification: DataClassification = DataClassification.RESTRICTED,
    git_sha: str = GIT_SHA,
) -> dict[str, str] | None:
    return _release_evidence_binding(
        identity=identity or _identity(),
        settings=settings,
        kind="release-evidence-component",
        classification=classification,
        release_id=RELEASE_ID,
        git_sha=git_sha,
        image_digest=IMAGE_DIGEST,
    )


def test_release_evidence_requires_dedicated_scope_and_restricted_data() -> None:
    settings = Settings()
    with pytest.raises(Forbidden, match="artifact:evidence:write"):
        _binding(settings, identity=_identity(evidence_scope=False))

    with pytest.raises(
        PlatformError,
        match="Release-evidence Artifacts require restricted classification",
    ):
        _binding(settings, classification=DataClassification.INTERNAL)


def test_release_evidence_must_match_deployed_git_and_image_identity() -> None:
    settings = Settings()
    settings.environment = "prod"
    settings.release_git_sha = GIT_SHA
    settings.release_image_digest = IMAGE_DIGEST

    assert _binding(settings) == BINDING
    with pytest.raises(
        PlatformError,
        match="Release-evidence identity does not match the deployed release",
    ):
        _binding(settings, git_sha="c" * 40)


def test_release_evidence_metadata_and_object_retention_are_at_least_365_days() -> None:
    settings = Settings(artifact_retention_restricted_days=90)
    started_at = datetime.now(UTC)
    payload = b'{"release":"evidence"}'
    record = _artifact_record(
        identity=_identity(),
        settings=settings,
        run_id=None,
        kind="release-evidence",
        classification=DataClassification.RESTRICTED,
        media_type="application/json",
        content=payload,
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        scan_status="malware_clean",
        scan_provenance={"malware": {"verdict": "clean"}},
        release_binding=BINDING,
    )

    assert record.retention_policy == "release-evidence@1:immutable:365d"
    assert record.expires_at is not None
    assert record.object_retain_until == record.expires_at
    assert record.expires_at >= started_at + timedelta(days=365)
    assert record.scan_provenance["release_binding"] == BINDING


def test_s3_object_metadata_round_trips_release_binding_fail_closed() -> None:
    payload = b"release evidence"
    artifact = ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="release-evidence",
        media_type="application/octet-stream",
        content=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        classification=DataClassification.RESTRICTED,
        created_by="release-publisher",
        retention_policy="release-evidence@1:immutable:365d",
        expires_at=datetime.now(UTC) + timedelta(days=365),
        scan_status="malware_clean",
        scan_provenance={"release_binding": BINDING},
    )

    object_metadata = S3ArtifactStore._release_binding_metadata(artifact)
    assert object_metadata == {
        "release-id": RELEASE_ID,
        "release-git-sha": GIT_SHA,
        "release-image-digest": IMAGE_DIGEST,
    }
    assert S3ArtifactStore._stored_release_binding(
        object_metadata,
        artifact.kind,
    ) == {"release_binding": BINDING}

    artifact.scan_provenance = {}
    with pytest.raises(PlatformError, match="missing immutable release identity"):
        S3ArtifactStore._release_binding_metadata(artifact)
