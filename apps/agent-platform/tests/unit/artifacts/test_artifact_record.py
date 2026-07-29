from __future__ import annotations

import hashlib
from uuid import uuid4

from agent_platform.application.records import ArtifactRecord
from agent_platform.domain.enums import DataClassification


def test_artifact_record_normalizes_legacy_string_classification_to_enum() -> None:
    content = b"evidence"

    record = ArtifactRecord(
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

    assert record.classification is DataClassification.INTERNAL
