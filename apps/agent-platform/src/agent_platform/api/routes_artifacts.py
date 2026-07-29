from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Annotated, Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse

from agent_platform.api.auth import require_scope
from agent_platform.api.dependencies import RequestIdentity, current_identity
from agent_platform.api.projections import artifact_view
from agent_platform.api.schemas import ArtifactMetadataView
from agent_platform.application.errors import Forbidden, NotFound, PlatformError
from agent_platform.application.ports import ArtifactStore, RunRepository
from agent_platform.application.records import ArtifactDownload, ArtifactRecord
from agent_platform.config import Settings
from agent_platform.domain.enums import DataClassification
from agent_platform.infrastructure.artifacts.malware import MalwareScanner
from agent_platform.infrastructure.artifacts.pipeline import (
    inspect_artifact_file_for_storage,
    inspect_artifact_for_storage,
)
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer
from agent_platform.infrastructure.artifacts.scanner import ArtifactScanner
from agent_platform.infrastructure.artifacts.streaming import stream_request_to_path

router = APIRouter(prefix="/v1/artifacts", tags=["artifacts"])

_RELEASE_EVIDENCE_KINDS = frozenset(
    {
        "release-evidence",
        "release-evidence-component",
        "release_evidence",
        "release_evidence_component",
    }
)
_RELEASE_EVIDENCE_MINIMUM_RETENTION_DAYS = 365
_RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@runtime_checkable
class ArtifactDownloadIssuer(Protocol):
    """Optional production extension; the base ArtifactStore remains compatible."""

    async def create_download(
        self,
        artifact: ArtifactRecord,
        *,
        principal_id: str,
        tenant_id: str,
        purpose: str,
        expires_in_seconds: int,
    ) -> ArtifactDownload: ...


@runtime_checkable
class ArtifactFileStore(Protocol):
    """Production extension for bounded-memory publication of staged files."""

    async def put_file(self, artifact: ArtifactRecord, path: Path) -> ArtifactRecord: ...


@runtime_checkable
class ArtifactMetadataStore(Protocol):
    """Production extension for metadata reads that never download object bytes."""

    async def get_metadata(
        self,
        artifact_id: UUID,
        tenant_id: str,
    ) -> ArtifactRecord: ...


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ArtifactMetadataView)
async def upload_artifact(
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
    run_id: Annotated[UUID | None, Query()] = None,
    kind: Annotated[str, Query()] = "document",
    classification: Annotated[DataClassification, Query()] = DataClassification.INTERNAL,
    media_type: Annotated[str, Header(alias="Content-Type")] = "application/octet-stream",
    evidence_release_id: Annotated[
        str | None,
        Header(alias="X-Evidence-Release-ID"),
    ] = None,
    evidence_git_sha: Annotated[
        str | None,
        Header(alias="X-Evidence-Git-SHA"),
    ] = None,
    evidence_image_digest: Annotated[
        str | None,
        Header(alias="X-Evidence-Image-Digest"),
    ] = None,
) -> ArtifactMetadataView:
    require_scope(identity.principal, "artifact:write")
    _require_artifact_resource(identity, hide=False)
    _require_classification(classification, identity, hide=False)
    if run_id is not None:
        await _run_repository(request).get(run_id, identity.principal.tenant_id)
    settings = _settings(request)
    release_binding = _release_evidence_binding(
        identity=identity,
        settings=settings,
        kind=kind,
        classification=classification,
        release_id=evidence_release_id,
        git_sha=evidence_git_sha,
        image_digest=evidence_image_digest,
    )

    scanner = cast(ArtifactScanner, request.app.state.container.artifact_scanner)
    malware_scanner = cast(
        MalwareScanner,
        request.app.state.container.artifact_malware_scanner,
    )
    sanitizer = cast(
        ArtifactContentSanitizer,
        request.app.state.container.artifact_sanitizer,
    )
    artifact_store = _artifact_store(request)
    if settings.artifact_backend == "s3":
        _validate_content_length(request, scanner.max_upload_bytes)

        with TemporaryDirectory(prefix="agent-artifact-") as temporary_directory:
            work_dir = Path(temporary_directory)
            staged = await stream_request_to_path(
                request.stream(),
                work_dir / "raw.upload",
                max_bytes=scanner.max_upload_bytes,
            )
            file_security = await inspect_artifact_file_for_storage(
                staged.path,
                media_type,
                work_dir=work_dir,
                structural_scanner=scanner,
                malware_scanner=malware_scanner,
                sanitizer=sanitizer,
                environment=settings.environment,
                artifact_backend=settings.artifact_backend,
                malware_scan_mode=settings.artifact_malware_scan_mode,
                max_in_memory_bytes=settings.artifact_max_in_memory_bytes,
            )
            artifact = _artifact_record(
                identity=identity,
                settings=settings,
                run_id=run_id,
                kind=kind,
                classification=classification,
                media_type=file_security.media_type,
                content=b"",
                size_bytes=file_security.size_bytes,
                sha256=file_security.sha256,
                scan_status=file_security.scan_status,
                scan_provenance={
                    **file_security.scan_provenance,
                    "transport": {
                        "mode": "request-stream-to-file",
                        "request_size_bytes": staged.size_bytes,
                        "request_sha256": staged.sha256,
                        "chunk_count": staged.chunk_count,
                        "max_request_chunk_bytes": staged.max_chunk_bytes,
                    },
                },
                release_binding=release_binding,
            )
            if not isinstance(artifact_store, ArtifactFileStore):
                raise PlatformError(
                    "ARTIFACT_STREAMING_STORE_REQUIRED",
                    "Object storage requires a bounded-memory Artifact file store",
                    http_status=503,
                )
            stored = await artifact_store.put_file(artifact, file_security.path)
    else:
        content = await _read_limited_content(request, scanner.max_upload_bytes)
        memory_security = await inspect_artifact_for_storage(
            content,
            media_type,
            structural_scanner=scanner,
            malware_scanner=malware_scanner,
            sanitizer=sanitizer,
            environment=settings.environment,
            artifact_backend=settings.artifact_backend,
            malware_scan_mode=settings.artifact_malware_scan_mode,
        )
        artifact = _artifact_record(
            identity=identity,
            settings=settings,
            run_id=run_id,
            kind=kind,
            classification=classification,
            media_type=memory_security.media_type,
            content=memory_security.content,
            size_bytes=len(memory_security.content),
            sha256=memory_security.sha256,
            scan_status=memory_security.scan_status,
            scan_provenance=memory_security.scan_provenance,
            release_binding=release_binding,
        )
        stored = await artifact_store.put(artifact)
    await _append_artifact_event(
        request,
        stored,
        "artifact.created",
        identity,
    )
    return artifact_view(stored)


@router.get("/{artifact_id}", response_model=ArtifactMetadataView)
async def get_artifact(
    artifact_id: UUID,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
    download: Annotated[bool, Query()] = False,
    purpose: Annotated[str | None, Query(max_length=256)] = None,
) -> ArtifactMetadataView | Response:
    _require_artifact_read_scope(identity)
    _require_artifact_resource(identity, artifact_id=artifact_id, hide=True)
    artifact_store = _artifact_store(request)
    if isinstance(artifact_store, ArtifactMetadataStore):
        artifact = await artifact_store.get_metadata(
            artifact_id,
            identity.principal.tenant_id,
        )
    else:
        artifact = await artifact_store.get(artifact_id, identity.principal.tenant_id)
    classification = _artifact_classification(artifact)
    _require_classification(classification, identity, artifact_id=artifact_id, hide=True)
    _require_active(artifact)
    if not download:
        return artifact_view(artifact)

    normalized_purpose = _download_purpose(purpose)
    if _settings(request).artifact_presign_enabled and isinstance(
        artifact_store, ArtifactDownloadIssuer
    ):
        ttl_seconds = _settings(request).artifact_presign_ttl_seconds
        issued = await artifact_store.create_download(
            artifact,
            principal_id=identity.principal.user_id,
            tenant_id=identity.principal.tenant_id,
            purpose=normalized_purpose,
            expires_in_seconds=ttl_seconds,
        )
        _validate_issued_download(issued, artifact, ttl_seconds)
        await _append_artifact_event(
            request,
            artifact,
            "artifact.accessed",
            identity,
            purpose=normalized_purpose,
            transport="presigned",
        )
        return JSONResponse(
            {
                "artifact_id": str(issued.artifact_id),
                "url": issued.url,
                "expires_at": issued.expires_at.isoformat(),
            }
        )

    if isinstance(artifact_store, ArtifactMetadataStore):
        artifact = await artifact_store.get(artifact_id, identity.principal.tenant_id)
        _require_active(artifact)
    await _append_artifact_event(
        request,
        artifact,
        "artifact.accessed",
        identity,
        purpose=normalized_purpose,
        transport="direct",
    )
    return Response(
        artifact.content,
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{artifact_id}"',
            "Digest": f"sha-256={artifact.sha256}",
        },
    )


@router.get("/{artifact_id}/content/sha256:{digest}")
async def get_artifact_content_by_digest(
    artifact_id: UUID,
    digest: str,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> Response:
    """Return immutable content only when the URL digest matches stored identity."""
    _require_artifact_read_scope(identity)
    _require_artifact_resource(identity, artifact_id=artifact_id, hide=True)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise NotFound("artifact", str(artifact_id))
    artifact_store = _artifact_store(request)
    if isinstance(artifact_store, ArtifactMetadataStore):
        metadata = await artifact_store.get_metadata(
            artifact_id,
            identity.principal.tenant_id,
        )
    else:
        metadata = await artifact_store.get(artifact_id, identity.principal.tenant_id)
    classification = _artifact_classification(metadata)
    _require_classification(classification, identity, artifact_id=artifact_id, hide=True)
    _require_active(metadata)
    if not hmac.compare_digest(metadata.sha256, digest):
        raise NotFound("artifact", str(artifact_id))
    settings = _settings(request)
    immutable_headers = {
        "Cache-Control": "private, no-store",
        "Content-Location": str(request.url.path),
        "Digest": f"sha-256={metadata.sha256}",
        "ETag": f'"sha256:{metadata.sha256}"',
    }
    if settings.artifact_presign_enabled and isinstance(
        artifact_store,
        ArtifactDownloadIssuer,
    ):
        ttl_seconds = settings.artifact_presign_ttl_seconds
        issued = await artifact_store.create_download(
            metadata,
            principal_id=identity.principal.user_id,
            tenant_id=identity.principal.tenant_id,
            purpose="content-addressed-read",
            expires_in_seconds=ttl_seconds,
        )
        _validate_issued_download(issued, metadata, ttl_seconds)
        await _append_artifact_event(
            request,
            metadata,
            "artifact.accessed",
            identity,
            purpose="content-addressed-read",
            transport="presigned-digest",
        )
        return RedirectResponse(
            issued.url,
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers=immutable_headers,
        )
    if settings.artifact_backend == "s3":
        raise PlatformError(
            "ARTIFACT_DIGEST_STREAMING_UNAVAILABLE",
            "Digest-addressed S3 reads require a bounded presigned transfer",
            http_status=503,
        )

    # Memory backends are bounded by artifact_max_in_memory_bytes. Production S3
    # always exits through the presigned branch above and never Body.read()s here.
    artifact = await artifact_store.get(artifact_id, identity.principal.tenant_id)
    actual_digest = hashlib.sha256(artifact.content).hexdigest()
    if not hmac.compare_digest(actual_digest, digest):
        raise PlatformError(
            "ARTIFACT_HASH_MISMATCH",
            "Stored Artifact content does not match its digest-addressed URL",
            http_status=503,
        )
    await _append_artifact_event(
        request,
        artifact,
        "artifact.accessed",
        identity,
        purpose="content-addressed-read",
        transport="direct-digest",
    )
    return Response(
        artifact.content,
        media_type=artifact.media_type,
        headers={
            **immutable_headers,
            "Content-Disposition": f'attachment; filename="{artifact_id}"',
        },
    )


@router.delete("/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_artifact(
    artifact_id: UUID,
    request: Request,
    identity: Annotated[RequestIdentity, Depends(current_identity)],
) -> Response:
    require_scope(identity.principal, "artifact:write")
    _require_artifact_resource(identity, artifact_id=artifact_id, hide=True)
    artifact_store = _artifact_store(request)
    try:
        if isinstance(artifact_store, ArtifactMetadataStore):
            artifact = await artifact_store.get_metadata(
                artifact_id,
                identity.principal.tenant_id,
            )
        else:
            artifact = await artifact_store.get(artifact_id, identity.principal.tenant_id)
    except NotFound:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    classification = _artifact_classification(artifact)
    _require_classification(classification, identity, artifact_id=artifact_id, hide=True)
    await artifact_store.delete(artifact_id, identity.principal.tenant_id)
    await _append_artifact_event(
        request,
        artifact,
        "artifact.deleted",
        identity,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _read_limited_content(request: Request, max_bytes: int) -> bytes:
    _validate_content_length(request, max_bytes)
    content = bytearray()
    async for chunk in request.stream():
        attempted_size = len(content) + len(chunk)
        if attempted_size > max_bytes:
            content.clear()
            raise _upload_limit_error(attempted_size, max_bytes)
        content.extend(chunk)
    return bytes(content)


def _validate_content_length(request: Request, max_bytes: int) -> None:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_bytes = int(content_length)
        except ValueError as exc:
            raise PlatformError(
                "INVALID_CONTENT_LENGTH",
                "Content-Length must be an integer",
                http_status=400,
            ) from exc
        if declared_bytes < 0:
            raise PlatformError(
                "INVALID_CONTENT_LENGTH",
                "Content-Length cannot be negative",
                http_status=400,
            )
        if declared_bytes > max_bytes:
            raise _upload_limit_error(declared_bytes, max_bytes)


def _release_evidence_binding(
    *,
    identity: RequestIdentity,
    settings: Settings,
    kind: str,
    classification: DataClassification,
    release_id: str | None,
    git_sha: str | None,
    image_digest: str | None,
) -> dict[str, str] | None:
    provided = (release_id, git_sha, image_digest)
    if kind not in _RELEASE_EVIDENCE_KINDS:
        if any(value is not None for value in provided):
            raise PlatformError(
                "RELEASE_EVIDENCE_KIND_REQUIRED",
                "Release identity headers are reserved for release-evidence Artifacts",
                http_status=400,
            )
        return None
    require_scope(identity.principal, "artifact:evidence:write")
    if classification is not DataClassification.RESTRICTED:
        raise PlatformError(
            "RELEASE_EVIDENCE_RESTRICTED_CLASSIFICATION_REQUIRED",
            "Release-evidence Artifacts require restricted classification",
            http_status=422,
        )
    if (
        release_id is None
        or _RELEASE_ID_PATTERN.fullmatch(release_id) is None
        or git_sha is None
        or _GIT_SHA_PATTERN.fullmatch(git_sha) is None
        or image_digest is None
        or _IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None
    ):
        raise PlatformError(
            "RELEASE_EVIDENCE_IDENTITY_INVALID",
            "Release-evidence identity headers are missing or malformed",
            http_status=422,
        )
    if settings.environment in {"staging", "prod"} and (
        git_sha != settings.release_git_sha or image_digest != settings.release_image_digest
    ):
        raise PlatformError(
            "RELEASE_EVIDENCE_DEPLOYMENT_IDENTITY_MISMATCH",
            "Release-evidence identity does not match the deployed release",
            http_status=409,
        )
    return {
        "release_id": release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
    }


def _artifact_record(
    *,
    identity: RequestIdentity,
    settings: Settings,
    run_id: UUID | None,
    kind: str,
    classification: DataClassification,
    media_type: str,
    content: bytes,
    size_bytes: int,
    sha256: str,
    scan_status: str,
    scan_provenance: dict[str, Any],
    release_binding: dict[str, str] | None,
) -> ArtifactRecord:
    retention_days = {
        DataClassification.PUBLIC: settings.artifact_retention_public_days,
        DataClassification.INTERNAL: settings.artifact_retention_internal_days,
        DataClassification.CONFIDENTIAL: settings.artifact_retention_confidential_days,
        DataClassification.RESTRICTED: settings.artifact_retention_restricted_days,
        DataClassification.SECRET: settings.artifact_retention_secret_days,
    }[classification]
    if kind in _RELEASE_EVIDENCE_KINDS:
        retention_days = max(
            retention_days,
            _RELEASE_EVIDENCE_MINIMUM_RETENTION_DAYS,
        )
    retention_policy = (
        f"release-evidence@1:immutable:{retention_days}d"
        if kind in _RELEASE_EVIDENCE_KINDS
        else f"classification:{classification.value}:{retention_days}d"
    )
    persisted_provenance = dict(scan_provenance)
    if release_binding is not None:
        persisted_provenance["release_binding"] = dict(release_binding)
    encryption_key_ref = _artifact_encryption_key(settings, classification)
    return ArtifactRecord(
        artifact_id=uuid4(),
        tenant_id=identity.principal.tenant_id,
        run_id=run_id,
        kind=kind,
        media_type=media_type,
        content=content,
        size_bytes=size_bytes,
        sha256=sha256,
        classification=classification,
        created_by=identity.principal.user_id,
        retention_policy=retention_policy,
        encryption_key_ref=encryption_key_ref,
        expires_at=datetime.now(UTC) + timedelta(days=retention_days),
        scan_status=scan_status,
        scan_provenance=persisted_provenance,
    )


def _artifact_encryption_key(
    settings: Settings,
    classification: DataClassification,
) -> str | None:
    if settings.artifact_backend != "s3":
        return None
    if classification is DataClassification.SECRET:
        return settings.artifact_secret_kms_key
    if classification in {
        DataClassification.CONFIDENTIAL,
        DataClassification.RESTRICTED,
    }:
        return settings.artifact_restricted_kms_key
    return settings.artifact_kms_key


def _upload_limit_error(size_bytes: int, max_bytes: int) -> PlatformError:
    return PlatformError(
        "ARTIFACT_SIZE_LIMIT_EXCEEDED",
        "Artifact exceeds the configured upload limit",
        http_status=413,
        context={
            "size_bytes": size_bytes,
            "max_upload_bytes": max_bytes,
        },
    )


def _require_artifact_read_scope(identity: RequestIdentity) -> None:
    principal = identity.principal
    readable = bool({"artifact:read", "runs:read"} & principal.scopes or "admin" in principal.roles)
    if not readable:
        raise Forbidden(
            "ARTIFACT_READ_SCOPE_REQUIRED",
            "Artifact metadata and downloads require an Artifact read scope",
        )


def _require_artifact_resource(
    identity: RequestIdentity,
    *,
    artifact_id: UUID | None = None,
    hide: bool,
) -> None:
    data_scope = identity.data_scope
    resource_allowed = "artifact" in data_scope.resource_types
    if artifact_id is not None and data_scope.resource_ids:
        resource_allowed = resource_allowed and bool(
            {
                str(artifact_id),
                f"artifact:{artifact_id}",
            }
            & data_scope.resource_ids
        )
    if resource_allowed:
        return
    if hide and artifact_id is not None:
        raise NotFound("artifact", str(artifact_id))
    raise Forbidden(
        "ARTIFACT_DATA_SCOPE_FORBIDDEN",
        "Authenticated data scope does not permit Artifact access",
    )


def _require_classification(
    classification: DataClassification,
    identity: RequestIdentity,
    *,
    artifact_id: UUID | None = None,
    hide: bool,
) -> None:
    if classification in identity.data_scope.classifications:
        return
    if hide and artifact_id is not None:
        raise NotFound("artifact", str(artifact_id))
    raise Forbidden(
        "ARTIFACT_CLASSIFICATION_FORBIDDEN",
        "Artifact classification is outside the authenticated data scope",
    )


def _artifact_classification(artifact: ArtifactRecord) -> DataClassification:
    try:
        return DataClassification(artifact.classification)
    except ValueError as exc:
        raise PlatformError(
            "ARTIFACT_CLASSIFICATION_INVALID",
            "Stored Artifact classification is invalid",
            http_status=503,
            context={"artifact_id": str(artifact.artifact_id)},
        ) from exc


def _require_active(artifact: ArtifactRecord) -> None:
    expires_at = artifact.expires_at
    if expires_at is None:
        return
    if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
        raise NotFound("artifact", str(artifact.artifact_id))


def _download_purpose(value: str | None) -> str:
    purpose = value.strip() if value is not None else ""
    if not purpose:
        raise PlatformError(
            "ARTIFACT_DOWNLOAD_PURPOSE_REQUIRED",
            "Artifact downloads require a non-empty purpose",
            http_status=400,
        )
    return purpose


def _validate_issued_download(
    issued: ArtifactDownload,
    artifact: ArtifactRecord,
    ttl_seconds: int,
) -> None:
    now = datetime.now(UTC)
    expires_at = issued.expires_at
    parsed = urlsplit(issued.url)
    valid_url = (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.username is None
        and parsed.password is None
    )
    valid_expiry = expires_at.tzinfo is not None and now < expires_at <= now + timedelta(
        seconds=ttl_seconds + 5
    )
    if issued.artifact_id != artifact.artifact_id or not valid_url or not valid_expiry:
        raise PlatformError(
            "ARTIFACT_DOWNLOAD_BINDING_INVALID",
            "Artifact store returned an invalid download binding",
            http_status=503,
            context={"artifact_id": str(artifact.artifact_id)},
        )


async def _append_artifact_event(
    request: Request,
    artifact: ArtifactRecord,
    event_type: str,
    identity: RequestIdentity,
    *,
    purpose: str | None = None,
    transport: str | None = None,
) -> None:
    if artifact.run_id is None:
        return
    runs = _run_repository(request)
    run = await runs.get(artifact.run_id, identity.principal.tenant_id)
    payload: dict[str, Any] = {
        "artifact_id": str(artifact.artifact_id),
        "classification": _artifact_classification(artifact).value,
        "principal_id": identity.principal.user_id,
        "sha256": artifact.sha256,
    }
    if event_type == "artifact.created":
        payload["scan_status"] = artifact.scan_status
        payload["scan_provenance"] = artifact.scan_provenance
    if purpose is not None:
        payload["purpose"] = purpose
    if transport is not None:
        payload["transport"] = transport
    await runs.append_event(
        run,
        event_type,
        payload,
        request.state.correlation_id,
    )


def _artifact_store(request: Request) -> ArtifactStore:
    return cast(ArtifactStore, request.app.state.container.store.artifacts)


def _run_repository(request: Request) -> RunRepository:
    return cast(RunRepository, request.app.state.container.store.runs)


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.container.settings)
