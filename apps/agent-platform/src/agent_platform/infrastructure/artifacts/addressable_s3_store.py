"""S3 content adapter whose durable URI matches the actual object key."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from agent_platform.application.records import ArtifactDownload, ArtifactRecord
from agent_platform.infrastructure.artifacts.s3_store import S3ArtifactStore


class AddressableS3ArtifactStore(S3ArtifactStore):
    """Expose the deterministic S3 URI required by PostgreSQL metadata."""

    def uri_for(self, artifact: ArtifactRecord) -> str:
        return f"s3://{self._bucket}/{self._key(artifact)}"

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload:
        if artifact.tenant_id != tenant_id:
            raise ValueError("ARTIFACT_DOWNLOAD_TENANT_MISMATCH")
        if not principal_id.strip() or not purpose.strip():
            raise ValueError("ARTIFACT_DOWNLOAD_AUDIT_CONTEXT_REQUIRED")
        if not 1 <= expires_in_seconds <= 900:
            raise ValueError("ARTIFACT_DOWNLOAD_EXPIRY_INVALID")
        parameters = {
            "Bucket": self._bucket,
            "Key": self._key(artifact),
            "ResponseContentType": artifact.media_type,
            "ResponseContentDisposition": f'attachment; filename="{artifact.artifact_id}"',
        }
        if artifact.object_version_id is not None:
            parameters["VersionId"] = artifact.object_version_id
        url = await asyncio.to_thread(
            self._client.generate_presigned_url,
            "get_object",
            Params=parameters,
            ExpiresIn=expires_in_seconds,
        )
        return ArtifactDownload(
            artifact_id=artifact.artifact_id,
            url=str(url),
            expires_at=datetime.now(UTC) + timedelta(seconds=expires_in_seconds),
        )
