from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import pytest

from agent_platform.application.errors import PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.persistence.production_store import (
    PostgresArtifactStore,
    _artifact_scan_provenance,
)
from agent_platform.infrastructure.persistence.session import AsyncSessionFactory


class MetadataOnlyContentStore:
    def uri_for(self, artifact: ArtifactRecord) -> str:
        return f"s3://bucket/{artifact.tenant_id}/{artifact.artifact_id}"


def artifact() -> ArtifactRecord:
    content = b"postgres provenance"
    digest = hashlib.sha256(content).hexdigest()
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id="tenant-a",
        run_id=None,
        kind="document",
        media_type="text/plain",
        content=content,
        sha256=digest,
        classification="internal",
        created_by="artifact-user",
        scan_status="malware_clean",
        scan_provenance={
            "malware": {
                "request_id": "request-1",
                "sha256": digest,
                "size_bytes": len(content),
                "verdict": "clean",
                "engine": "controlled-av",
                "engine_version": "2026.07.24",
                "scanned_at": datetime.now(UTC).isoformat(),
                "evidence_id": "evidence-1",
            }
        },
    )


def test_postgres_metadata_uses_existing_source_json_extension_for_scan_evidence() -> None:
    record = artifact()
    store = PostgresArtifactStore(
        cast(AsyncSessionFactory, object()),
        cast(Any, MetadataOnlyContentStore()),
    )

    values = store._metadata_values(record)

    assert values["source_json"] == {
        "scan_status": "malware_clean",
        "scan_provenance": record.scan_provenance,
    }
    assert _artifact_scan_provenance(values["source_json"]) == record.scan_provenance


def test_postgres_readback_rejects_malformed_scan_provenance() -> None:
    with pytest.raises(PlatformError, match="ARTIFACT_SCAN_PROVENANCE_INVALID"):
        _artifact_scan_provenance({"scan_provenance": "not-an-object"})
