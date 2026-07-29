from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

from agent_platform.application.errors import NotFound, PlatformError
from agent_platform.application.records import ArtifactRecord
from agent_platform.infrastructure.artifacts.trusted_generated import (
    validate_trusted_generated_artifact,
)

_RELEASE_EVIDENCE_KINDS = frozenset(
    {
        "release-evidence",
        "release-evidence-component",
        "release_evidence",
        "release_evidence_component",
    }
)
_RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class S3ArtifactStore:
    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        kms_key_id: str | None,
        environment: str,
        staging_bucket: str | None = None,
        multipart_part_size_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if not 5 * 1024 * 1024 <= multipart_part_size_bytes <= 64 * 1024 * 1024:
            raise ValueError("ARTIFACT_MULTIPART_PART_SIZE_INVALID")
        self._client = client
        self._bucket = bucket
        self._kms_key_id = kms_key_id
        self._environment = environment
        self._staging_bucket = staging_bucket
        self._multipart_part_size_bytes = multipart_part_size_bytes

    def _key(self, artifact: ArtifactRecord) -> str:
        run_part = str(artifact.run_id) if artifact.run_id else "unbound"
        return (
            f"{self._environment}/tenant/{artifact.tenant_id}/"
            f"run/{run_part}/artifacts/{artifact.artifact_id}"
        )

    async def put(self, artifact: ArtifactRecord) -> ArtifactRecord:
        digest = hashlib.sha256(artifact.content).hexdigest()
        if len(artifact.content) != artifact.size_bytes or digest != artifact.sha256:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Artifact content hash does not match metadata",
            )
        evidence_type, evidence = self._validated_storage_evidence(artifact)
        encryption = self._encryption(artifact)

        governance = self._final_object_governance(artifact)
        response = await asyncio.to_thread(
            self._client.put_object,
            Bucket=self._bucket,
            Key=self._key(artifact),
            Body=artifact.content,
            ContentType=artifact.media_type,
            Metadata=self._storage_metadata(
                artifact,
                evidence_type=evidence_type,
                evidence=evidence,
            ),
            **encryption,
            **governance,
        )
        await asyncio.to_thread(
            self._capture_final_object_metadata,
            artifact,
            response=response,
            key=self._key(artifact),
            governance=governance,
        )
        return artifact

    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord:
        """Publish a staged file through a verified temporary multipart object."""
        evidence_type, evidence = self._validated_storage_evidence(artifact)
        metadata = self._storage_metadata(
            artifact,
            evidence_type=evidence_type,
            evidence=evidence,
        )
        version_id, retain_until = await asyncio.to_thread(
            self._put_file_sync,
            artifact,
            path,
            metadata,
        )
        artifact.object_version_id = version_id
        artifact.object_retain_until = retain_until
        return artifact

    def _put_file_sync(
        self,
        artifact: ArtifactRecord,
        path: Path,
        metadata: dict[str, str],
    ) -> tuple[str | None, datetime | None]:
        actual_sha256, actual_size = self._file_identity(path)
        if actual_sha256 != artifact.sha256 or actual_size != artifact.size_bytes:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Staged Artifact identity does not match security metadata",
            )
        encryption = self._encryption(artifact)
        final_key = self._key(artifact)
        staging_bucket = self._staging_bucket or self._bucket
        if self._environment in {"staging", "prod"} and staging_bucket == self._bucket:
            raise PlatformError(
                "ARTIFACT_STAGING_BUCKET_REQUIRED",
                (
                    "Multipart staging must use an unlocked bucket separate from "
                    "governed final objects"
                ),
                http_status=503,
            )
        temporary_key = (
            f"{self._environment}/tenant/{artifact.tenant_id}/.pending/"
            f"{artifact.artifact_id}/{uuid4()}"
        )
        created = self._client.create_multipart_upload(
            Bucket=staging_bucket,
            Key=temporary_key,
            ContentType=artifact.media_type,
            Metadata=metadata,
            **encryption,
        )
        upload_id = created.get("UploadId") if isinstance(created, Mapping) else None
        if not isinstance(upload_id, str) or not upload_id:
            raise PlatformError(
                "ARTIFACT_MULTIPART_PROTOCOL_INVALID",
                "S3 did not return a multipart upload identifier",
                retryable=True,
                http_status=503,
            )
        parts: list[dict[str, Any]] = []
        try:
            with path.open("rb") as handle:
                part_number = 1
                while chunk := handle.read(self._multipart_part_size_bytes):
                    uploaded = self._client.upload_part(
                        Bucket=staging_bucket,
                        Key=temporary_key,
                        UploadId=upload_id,
                        PartNumber=part_number,
                        Body=chunk,
                    )
                    etag = uploaded.get("ETag") if isinstance(uploaded, Mapping) else None
                    if not isinstance(etag, str) or not etag:
                        raise PlatformError(
                            "ARTIFACT_MULTIPART_PROTOCOL_INVALID",
                            "S3 multipart part response omitted ETag",
                            retryable=True,
                            http_status=503,
                        )
                    parts.append({"ETag": etag, "PartNumber": part_number})
                    part_number += 1
            self._client.complete_multipart_upload(
                Bucket=staging_bucket,
                Key=temporary_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
        except Exception as exc:
            try:
                self._client.abort_multipart_upload(
                    Bucket=staging_bucket,
                    Key=temporary_key,
                    UploadId=upload_id,
                )
            except Exception as abort_exc:
                raise PlatformError(
                    "ARTIFACT_MULTIPART_ABORT_FAILED",
                    "Multipart upload failed and its temporary object could not be aborted",
                    retryable=True,
                    http_status=503,
                ) from abort_exc
            raise exc

        try:
            self._verify_object(staging_bucket, temporary_key, artifact)
            governance = self._final_object_governance(artifact)
            response = self._client.copy_object(
                Bucket=self._bucket,
                CopySource={"Bucket": staging_bucket, "Key": temporary_key},
                Key=final_key,
                MetadataDirective="COPY",
                **encryption,
                **governance,
            )
            version_id, retain_until = self._capture_final_object_metadata(
                artifact,
                response=response,
                key=final_key,
                governance=governance,
            )
        except Exception:
            self._delete_cleanup(staging_bucket, temporary_key)
            # A copied final version may already be locked. Never bypass governance
            # to hide a failed readback; deterministic-key reconciliation owns it.
            raise
        self._delete_cleanup(staging_bucket, temporary_key)
        return version_id, retain_until

    def _verify_object(
        self,
        bucket: str,
        key: str,
        artifact: ArtifactRecord,
    ) -> Mapping[str, Any]:
        head = self._client.head_object(Bucket=bucket, Key=key)
        metadata = head.get("Metadata") if isinstance(head, Mapping) else None
        if (
            not isinstance(metadata, Mapping)
            or head.get("ContentLength") != artifact.size_bytes
            or metadata.get("sha256") != artifact.sha256
        ):
            raise PlatformError(
                "ARTIFACT_FINAL_VERIFICATION_FAILED",
                "S3 object size or checksum metadata failed final verification",
                retryable=True,
                http_status=503,
            )
        return cast(Mapping[str, Any], head)

    def _final_object_governance(self, artifact: ArtifactRecord) -> dict[str, Any]:
        if self._environment not in {"staging", "prod"}:
            return {}
        now = datetime.now(UTC)
        retain_until = (
            artifact.object_retain_until or artifact.expires_at or now + timedelta(days=90)
        )
        release_evidence_kinds = {
            "release-evidence",
            "release-evidence-component",
            "release_evidence",
            "release_evidence_component",
        }
        if artifact.kind in release_evidence_kinds:
            if artifact.classification.value != "restricted":
                raise PlatformError(
                    "RELEASE_EVIDENCE_RESTRICTED_CLASSIFICATION_REQUIRED",
                    "Release-evidence Artifacts must use restricted classification",
                )
            minimum_retain_until = now + timedelta(days=365)
            if retain_until < minimum_retain_until:
                retain_until = minimum_retain_until
            if artifact.retention_policy == "default":
                artifact.retention_policy = "release-evidence@1:immutable:365d"
        if retain_until.tzinfo is None or retain_until.utcoffset() is None:
            raise PlatformError(
                "ARTIFACT_OBJECT_RETAIN_UNTIL_TIMEZONE_REQUIRED",
                "Artifact object retention requires a timezone-aware timestamp",
            )
        artifact.object_retain_until = retain_until.astimezone(UTC)
        if artifact.object_retain_until <= datetime.now(UTC):
            raise PlatformError(
                "ARTIFACT_OBJECT_RETENTION_EXPIRED",
                "A final Artifact cannot be published with expired object retention",
            )
        governance: dict[str, Any] = {
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": artifact.object_retain_until,
        }
        if artifact.legal_hold_status == "on":
            governance["ObjectLockLegalHoldStatus"] = "ON"
        return governance

    def _capture_final_object_metadata(
        self,
        artifact: ArtifactRecord,
        *,
        response: Any,
        key: str,
        governance: Mapping[str, Any],
    ) -> tuple[str | None, datetime | None]:
        response_version = response.get("VersionId") if isinstance(response, Mapping) else None
        if not governance:
            version_id = (
                str(response_version).strip()
                if isinstance(response_version, str) and response_version.strip()
                else None
            )
            artifact.object_version_id = version_id
            return version_id, artifact.object_retain_until

        head = self._verify_object(self._bucket, key, artifact)
        raw_version = head.get("VersionId") or response_version
        if not isinstance(raw_version, str) or not raw_version.strip():
            raise PlatformError(
                "ARTIFACT_OBJECT_VERSION_REQUIRED",
                "Governed final Artifact did not return a version identifier",
                retryable=True,
                http_status=503,
            )
        retain_until = head.get("ObjectLockRetainUntilDate")
        if not isinstance(retain_until, datetime):
            raise PlatformError(
                "ARTIFACT_OBJECT_RETENTION_READBACK_FAILED",
                "Governed final Artifact did not return its retain-until timestamp",
                retryable=True,
                http_status=503,
            )
        retain_until = retain_until.astimezone(UTC)
        expected_retain_until = governance["ObjectLockRetainUntilDate"]
        if (
            head.get("ObjectLockMode") != governance.get("ObjectLockMode")
            or retain_until < expected_retain_until
            or head.get("ServerSideEncryption") != "aws:kms"
            or head.get("SSEKMSKeyId") != (artifact.encryption_key_ref or self._kms_key_id)
        ):
            raise PlatformError(
                "ARTIFACT_OBJECT_GOVERNANCE_READBACK_FAILED",
                "Final Artifact version, encryption, or Object Lock did not match policy",
                retryable=True,
                http_status=503,
            )
        expected_hold = governance.get("ObjectLockLegalHoldStatus")
        if expected_hold is not None and head.get("ObjectLockLegalHoldStatus") != expected_hold:
            raise PlatformError(
                "ARTIFACT_LEGAL_HOLD_READBACK_FAILED",
                "Final Artifact legal hold did not match policy",
                retryable=True,
                http_status=503,
            )
        artifact.object_version_id = raw_version.strip()
        artifact.object_retain_until = retain_until
        return artifact.object_version_id, retain_until

    def _delete_cleanup(self, bucket: str, key: str) -> None:
        try:
            self._client.delete_object(Bucket=bucket, Key=key)
        except Exception as exc:
            raise PlatformError(
                "ARTIFACT_TEMPORARY_OBJECT_CLEANUP_FAILED",
                "S3 temporary Artifact object could not be removed",
                retryable=True,
                http_status=503,
            ) from exc

    @staticmethod
    def _file_identity(path: Path) -> tuple[str, int]:
        digest = hashlib.sha256()
        size_bytes = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)
        return digest.hexdigest(), size_bytes

    def _encryption(self, artifact: ArtifactRecord) -> dict[str, str]:
        kms_key_id = artifact.encryption_key_ref or self._kms_key_id
        return (
            {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key_id}
            if kms_key_id
            else {"ServerSideEncryption": "AES256"}
        )

    @staticmethod
    def _release_binding_metadata(artifact: ArtifactRecord) -> dict[str, str]:
        raw = artifact.scan_provenance.get("release_binding")
        if artifact.kind not in _RELEASE_EVIDENCE_KINDS:
            if raw is not None:
                raise PlatformError(
                    "RELEASE_EVIDENCE_KIND_REQUIRED",
                    "Release binding cannot be stored on a non-release Artifact",
                    http_status=503,
                )
            return {}
        if not isinstance(raw, Mapping):
            raise PlatformError(
                "RELEASE_EVIDENCE_BINDING_REQUIRED",
                "Release-evidence Artifact is missing immutable release identity",
                http_status=503,
            )
        release_id = raw.get("release_id")
        git_sha = raw.get("git_sha")
        image_digest = raw.get("image_digest")
        if (
            not isinstance(release_id, str)
            or _RELEASE_ID_PATTERN.fullmatch(release_id) is None
            or not isinstance(git_sha, str)
            or _GIT_SHA_PATTERN.fullmatch(git_sha) is None
            or not isinstance(image_digest, str)
            or _IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None
        ):
            raise PlatformError(
                "RELEASE_EVIDENCE_BINDING_INVALID",
                "Release-evidence Artifact identity is malformed",
                http_status=503,
            )
        return {
            "release-id": release_id,
            "release-git-sha": git_sha,
            "release-image-digest": image_digest,
        }

    @staticmethod
    def _stored_release_binding(
        metadata: Mapping[str, str],
        kind: str,
    ) -> dict[str, Any]:
        raw_values = {
            "release_id": metadata.get("release-id"),
            "git_sha": metadata.get("release-git-sha"),
            "image_digest": metadata.get("release-image-digest"),
        }
        if kind not in _RELEASE_EVIDENCE_KINDS:
            if any(value is not None for value in raw_values.values()):
                raise PlatformError(
                    "RELEASE_EVIDENCE_KIND_REQUIRED",
                    "Stored release identity is attached to a non-release Artifact",
                    http_status=503,
                )
            return {}
        release_id = raw_values["release_id"]
        git_sha = raw_values["git_sha"]
        image_digest = raw_values["image_digest"]
        if (
            not isinstance(release_id, str)
            or _RELEASE_ID_PATTERN.fullmatch(release_id) is None
            or not isinstance(git_sha, str)
            or _GIT_SHA_PATTERN.fullmatch(git_sha) is None
            or not isinstance(image_digest, str)
            or _IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None
        ):
            raise PlatformError(
                "RELEASE_EVIDENCE_BINDING_INVALID",
                "Stored release-evidence identity is missing or malformed",
                http_status=503,
            )
        return {
            "release_binding": {
                "release_id": release_id,
                "git_sha": git_sha,
                "image_digest": image_digest,
            }
        }

    @staticmethod
    def _storage_metadata(
        artifact: ArtifactRecord,
        *,
        evidence_type: str,
        evidence: Mapping[str, Any],
    ) -> dict[str, str]:
        metadata = {
            "tenant-id": artifact.tenant_id,
            "sha256": artifact.sha256,
            "classification": artifact.classification.value,
            "scan-status": artifact.scan_status,
            "scan-evidence-type": evidence_type,
            "artifact-kind": artifact.kind,
            "retention-policy": artifact.retention_policy,
            "legal-hold-status": artifact.legal_hold_status,
        }
        metadata.update(S3ArtifactStore._release_binding_metadata(artifact))
        if evidence_type == "external-malware-clean":
            metadata.update(
                {
                    "scan-request-id": str(evidence["request_id"]),
                    "scan-evidence-id": str(evidence["evidence_id"]),
                    "scan-engine": str(evidence["engine"]),
                    "scan-engine-version": str(evidence["engine_version"]),
                    "scan-time": str(evidence["scanned_at"]),
                    "scan-verdict": str(evidence["verdict"]),
                    "scan-size": str(evidence["size_bytes"]),
                }
            )
            return metadata

        trusted = evidence["trusted_generated"]
        sanitization = evidence["sanitization"]
        if not isinstance(trusted, Mapping) or not isinstance(sanitization, Mapping):
            raise PlatformError(
                "ARTIFACT_TRUSTED_GENERATED_PROVENANCE_INVALID",
                "Trusted-generated provenance is incomplete",
                http_status=503,
            )
        metadata.update(
            {
                "scan-size": str(trusted["size_bytes"]),
                "trusted-source": str(trusted["source"]),
                "trusted-source-version": str(trusted["source_version"]),
                "trusted-schema-version": str(trusted["schema_version"]),
                "trusted-serialization": str(trusted["serialization"]),
                "trusted-serialization-version": str(trusted["serialization_version"]),
                "sanitization-status": str(sanitization["status"]),
                "sanitization-method": str(sanitization["method"]),
                "sanitization-version": str(sanitization["version"]),
                "sanitization-original-sha256": str(sanitization["original_sha256"]),
                "sanitization-final-sha256": str(sanitization["sanitized_sha256"]),
            }
        )
        return metadata

    async def _find_key(self, artifact_id: UUID, tenant_id: str) -> str:
        prefix = f"{self._environment}/tenant/{tenant_id}/"
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            request: dict[str, Any] = {
                "Bucket": self._bucket,
                "Prefix": prefix,
                "MaxKeys": 1_000,
            }
            if continuation_token is not None:
                request["ContinuationToken"] = continuation_token
            response = await asyncio.to_thread(
                self._client.list_objects_v2,
                **request,
            )
            contents = response.get("Contents", [])
            if not isinstance(contents, list):
                raise self._invalid_listing("Contents must be a list")
            for item in contents:
                if not isinstance(item, dict):
                    raise self._invalid_listing("Contents contains an invalid object")
                raw_key = item.get("Key")
                if not isinstance(raw_key, str):
                    raise self._invalid_listing("Contents contains an invalid object key")
                key = raw_key
                if not key.startswith(prefix):
                    raise self._invalid_listing("Object key escaped the tenant prefix")
                if key.endswith(f"/{artifact_id}"):
                    return key

            if response.get("IsTruncated") is not True:
                break
            next_token = response.get("NextContinuationToken")
            if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
                raise self._invalid_listing(
                    "Truncated response did not advance its continuation token"
                )
            seen_tokens.add(next_token)
            continuation_token = next_token

        raise NotFound("artifact", str(artifact_id))

    @staticmethod
    def _invalid_listing(reason: str) -> PlatformError:
        return PlatformError(
            "ARTIFACT_LISTING_PAGINATION_INVALID",
            f"S3 returned an invalid paginated listing: {reason}",
            retryable=True,
            http_status=503,
        )

    async def get_metadata(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        """Read governed object identity without materializing the object Body."""
        key = await self._find_key(artifact_id, tenant_id)
        result = await asyncio.to_thread(
            self._client.head_object,
            Bucket=self._bucket,
            Key=key,
        )
        metadata = result.get("Metadata", {})
        if not isinstance(metadata, Mapping):
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 evidence metadata is missing",
                http_status=503,
            )
        digest = metadata.get("sha256")
        size_bytes = result.get("ContentLength")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
        ):
            raise PlatformError(
                "ARTIFACT_STORAGE_IDENTITY_INVALID",
                "Stored S3 object size or hash metadata is invalid",
                http_status=503,
            )
        scan_status = metadata.get("scan-status", "")
        if scan_status == "malware_clean":
            scan_provenance = self._stored_malware_provenance(
                metadata,
                digest,
                size_bytes,
            )
        elif scan_status == "trusted_generated":
            scan_provenance = self._stored_trusted_provenance(
                metadata,
                digest,
                size_bytes,
            )
        else:
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 object lacks recognized storage evidence",
                http_status=503,
            )
        kind = metadata.get("artifact-kind", "")
        if not isinstance(kind, str) or not kind:
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 object lacks Artifact kind evidence",
                http_status=503,
            )
        scan_provenance.update(self._stored_release_binding(metadata, kind))
        retain_until = result.get("ObjectLockRetainUntilDate")
        if retain_until is not None and not isinstance(retain_until, datetime):
            raise PlatformError(
                "ARTIFACT_OBJECT_RETENTION_READBACK_FAILED",
                "Stored S3 retain-until metadata is invalid",
                http_status=503,
            )
        legal_hold_status = (
            "on"
            if result.get("ObjectLockLegalHoldStatus") == "ON"
            else str(metadata.get("legal-hold-status", "none"))
        )
        return ArtifactRecord(
            artifact_id=artifact_id,
            tenant_id=tenant_id,
            run_id=None,
            kind=kind,
            media_type=result.get("ContentType", "application/octet-stream"),
            content=b"",
            size_bytes=size_bytes,
            sha256=digest,
            classification=metadata.get("classification", "internal"),
            created_by="artifact-service",
            retention_policy=str(metadata.get("retention-policy", "default")),
            object_version_id=(
                str(result["VersionId"]) if isinstance(result.get("VersionId"), str) else None
            ),
            object_retain_until=retain_until,
            expires_at=retain_until,
            legal_hold_status=legal_hold_status,
            scan_status=str(scan_status),
            scan_provenance=scan_provenance,
            created_at=result.get("LastModified", datetime.now(UTC)),
        )

    async def get(self, artifact_id: UUID, tenant_id: str) -> ArtifactRecord:
        key = await self._find_key(artifact_id, tenant_id)
        result = await asyncio.to_thread(
            self._client.get_object,
            Bucket=self._bucket,
            Key=key,
        )
        stream = result["Body"]
        try:
            body = await asyncio.to_thread(stream.read)
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                await asyncio.to_thread(close)
        metadata = result.get("Metadata", {})
        if not isinstance(metadata, Mapping):
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 evidence metadata is missing",
                http_status=503,
            )
        digest = hashlib.sha256(body).hexdigest()
        if metadata.get("sha256") != digest:
            raise PlatformError(
                "ARTIFACT_HASH_MISMATCH",
                "Stored Artifact failed integrity verification",
                http_status=503,
            )

        scan_status = metadata.get("scan-status", "")
        if scan_status == "malware_clean":
            scan_provenance = self._stored_malware_provenance(
                metadata,
                digest,
                len(body),
            )
        elif scan_status == "trusted_generated":
            scan_provenance = self._stored_trusted_provenance(
                metadata,
                digest,
                len(body),
            )
        else:
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 object lacks recognized storage evidence",
                http_status=503,
            )

        kind = metadata.get("artifact-kind", "")
        if not isinstance(kind, str) or not kind:
            raise PlatformError(
                "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
                "Stored S3 object lacks Artifact kind evidence",
                http_status=503,
            )
        scan_provenance.update(self._stored_release_binding(metadata, kind))
        retain_until = result.get("ObjectLockRetainUntilDate")
        if retain_until is not None and not isinstance(retain_until, datetime):
            raise PlatformError(
                "ARTIFACT_OBJECT_RETENTION_READBACK_FAILED",
                "Stored S3 retain-until metadata is invalid",
                http_status=503,
            )
        artifact = ArtifactRecord(
            artifact_id=artifact_id,
            tenant_id=tenant_id,
            run_id=None,
            kind=kind,
            media_type=result.get("ContentType", "application/octet-stream"),
            content=body,
            sha256=digest,
            classification=metadata.get("classification", "internal"),
            created_by="artifact-service",
            retention_policy=str(metadata.get("retention-policy", "default")),
            object_version_id=(
                str(result["VersionId"]) if isinstance(result.get("VersionId"), str) else None
            ),
            object_retain_until=retain_until,
            expires_at=retain_until,
            legal_hold_status=(
                "on"
                if result.get("ObjectLockLegalHoldStatus") == "ON"
                else str(metadata.get("legal-hold-status", "none"))
            ),
            scan_status=scan_status,
            scan_provenance=scan_provenance,
            created_at=result.get("LastModified", datetime.now(UTC)),
        )
        if scan_status == "trusted_generated":
            validate_trusted_generated_artifact(artifact)
        return artifact

    @classmethod
    def _validated_storage_evidence(
        cls,
        artifact: ArtifactRecord,
    ) -> tuple[str, Mapping[str, Any]]:
        if artifact.scan_status == "malware_clean":
            return "external-malware-clean", cls._validated_malware_evidence(artifact)
        if artifact.scan_status == "trusted_generated":
            validate_trusted_generated_artifact(artifact)
            return "trusted-generated", {
                "trusted_generated": artifact.scan_provenance["trusted_generated"],
                "sanitization": artifact.scan_provenance["sanitization"],
            }
        raise PlatformError(
            "ARTIFACT_STORAGE_EVIDENCE_REQUIRED",
            "Artifact storage requires exact malware-clean or trusted-generated evidence",
            http_status=503,
        )

    @staticmethod
    def _validated_malware_evidence(artifact: ArtifactRecord) -> Mapping[str, Any]:
        raw = artifact.scan_provenance.get("malware")
        if (
            artifact.scan_status != "malware_clean"
            or not isinstance(raw, Mapping)
            or raw.get("verdict") != "clean"
        ):
            raise PlatformError(
                "ARTIFACT_MALWARE_SCAN_REQUIRED",
                "Exact malware-clean evidence is required before S3 storage",
                http_status=503,
            )
        if raw.get("sha256") != artifact.sha256 or raw.get("size_bytes") != artifact.size_bytes:
            raise PlatformError(
                "ARTIFACT_MALWARE_SCAN_BINDING_INVALID",
                "Malware scan evidence does not bind the S3 object bytes",
                http_status=503,
            )
        required = (
            "request_id",
            "evidence_id",
            "engine",
            "engine_version",
            "scanned_at",
        )
        if any(not isinstance(raw.get(field), str) or not raw[field].strip() for field in required):
            raise PlatformError(
                "ARTIFACT_MALWARE_SCAN_RESPONSE_INVALID",
                "Malware scan evidence is incomplete",
                http_status=503,
            )
        return raw

    @staticmethod
    def _stored_malware_provenance(
        metadata: Mapping[str, str],
        sha256: str,
        size_bytes: int,
    ) -> dict[str, Any]:
        try:
            scan_size = int(metadata["scan-size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PlatformError(
                "ARTIFACT_MALWARE_SCAN_RESPONSE_INVALID",
                "Stored S3 malware scan metadata is incomplete",
                http_status=503,
            ) from exc
        malware = {
            "request_id": metadata.get("scan-request-id", ""),
            "sha256": metadata.get("sha256", ""),
            "size_bytes": scan_size,
            "verdict": metadata.get("scan-verdict", ""),
            "engine": metadata.get("scan-engine", ""),
            "engine_version": metadata.get("scan-engine-version", ""),
            "scanned_at": metadata.get("scan-time", ""),
            "evidence_id": metadata.get("scan-evidence-id", ""),
        }
        if (
            metadata.get("scan-status") != "malware_clean"
            or metadata.get("scan-evidence-type") != "external-malware-clean"
            or malware["verdict"] != "clean"
            or malware["sha256"] != sha256
            or malware["size_bytes"] != size_bytes
            or any(not str(value).strip() for value in malware.values())
        ):
            raise PlatformError(
                "ARTIFACT_MALWARE_SCAN_BINDING_INVALID",
                "Stored S3 malware scan metadata does not bind the object",
                http_status=503,
            )
        return {"malware": malware}

    @staticmethod
    def _stored_trusted_provenance(
        metadata: Mapping[str, str],
        sha256: str,
        size_bytes: int,
    ) -> dict[str, Any]:
        try:
            scan_size = int(metadata["scan-size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PlatformError(
                "ARTIFACT_TRUSTED_GENERATED_PROVENANCE_INVALID",
                "Stored S3 trusted-generated metadata is incomplete",
                http_status=503,
            ) from exc
        if (
            metadata.get("scan-status") != "trusted_generated"
            or metadata.get("scan-evidence-type") != "trusted-generated"
            or metadata.get("sha256") != sha256
            or scan_size != size_bytes
        ):
            raise PlatformError(
                "ARTIFACT_TRUSTED_GENERATED_BINDING_INVALID",
                "Stored S3 trusted-generated metadata does not bind the object",
                http_status=503,
            )
        return {
            "trusted_generated": {
                "schema_version": metadata.get("trusted-schema-version", ""),
                "source": metadata.get("trusted-source", ""),
                "source_version": metadata.get("trusted-source-version", ""),
                "kind": metadata.get("artifact-kind", ""),
                "media_type": "application/json",
                "serialization": metadata.get("trusted-serialization", ""),
                "serialization_version": metadata.get(
                    "trusted-serialization-version",
                    "",
                ),
                "sha256": sha256,
                "size_bytes": scan_size,
            },
            "sanitization": {
                "status": metadata.get("sanitization-status", ""),
                "method": metadata.get("sanitization-method", ""),
                "version": metadata.get("sanitization-version", ""),
                "original_sha256": metadata.get(
                    "sanitization-original-sha256",
                    "",
                ),
                "sanitized_sha256": metadata.get(
                    "sanitization-final-sha256",
                    "",
                ),
            },
        }

    async def delete(self, artifact_id: UUID, tenant_id: str) -> None:
        key = await self._find_key(artifact_id, tenant_id)
        head = await asyncio.to_thread(
            self._client.head_object,
            Bucket=self._bucket,
            Key=key,
        )
        if head.get("ObjectLockLegalHoldStatus") == "ON":
            raise PlatformError(
                "ARTIFACT_LEGAL_HOLD_ACTIVE",
                "Artifact deletion is blocked by an active object-store legal hold",
                http_status=409,
            )
        retain_until = head.get("ObjectLockRetainUntilDate")
        if isinstance(retain_until, datetime) and retain_until > datetime.now(UTC):
            raise PlatformError(
                "ARTIFACT_RETENTION_ACTIVE",
                "Artifact deletion is blocked by object-store retention",
                http_status=409,
                context={"retain_until": retain_until.isoformat()},
            )
        request: dict[str, Any] = {"Bucket": self._bucket, "Key": key}
        version_id = head.get("VersionId")
        if isinstance(version_id, str) and version_id.strip():
            request["VersionId"] = version_id.strip()
        await asyncio.to_thread(self._client.delete_object, **request)
