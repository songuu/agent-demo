"""Publish release evidence to governed, digest-addressed Artifact storage."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from jsonschema import Draft202012Validator, FormatChecker

from agent_platform.application.errors import PlatformError
from agent_platform.infrastructure.artifacts.sanitizer import ArtifactContentSanitizer

PLATFORM_ROOT = Path(__file__).resolve().parents[1]
PUBLICATION_SCHEMA = PLATFORM_ROOT / "deploy" / "ci" / "published-evidence-assets.schema.json"
_ASSET_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHUNK_BYTES = 1024 * 1024
_SIGNED_OPAQUE_COMPONENT_ASSETS = frozenset(
    {
        "canary",
        "canary_signature_bundle",
        "foundation_attestation",
        "foundation_attestation_signature_bundle",
        "release_approvals",
        "release_approvals_signature_bundle",
    }
)

JsonObject = dict[str, Any]


@dataclass(frozen=True, slots=True)
class PreparedAsset:
    content: bytes
    media_type: str
    sha256: str
    size_bytes: int


def _load_object(path: Path) -> JsonObject:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _parse_asset_specs(values: Sequence[str]) -> dict[str, Path]:
    assets: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if separator != "=" or not _ASSET_NAME.fullmatch(name) or not raw_path.strip():
            raise ValueError(f"EVIDENCE_ASSET_SPEC_INVALID: {value!r}")
        if name in assets:
            raise ValueError(f"EVIDENCE_ASSET_NAME_DUPLICATED: {name}")
        path = Path(raw_path).resolve()
        if not path.is_file():
            raise ValueError(f"EVIDENCE_ASSET_FILE_REQUIRED: {name}")
        assets[name] = path
    if not assets:
        raise ValueError("EVIDENCE_ASSETS_REQUIRED")
    return assets


def _declared_media_type(path: Path) -> str:
    lowered = path.name.lower()
    if lowered.endswith(".sigstore.json"):
        # Sigstore bundles are signed transport objects; preserve their exact bytes.
        return "application/octet-stream"
    if lowered.endswith((".json", ".spdx.json", ".attestation.json")):
        return "application/json"
    if lowered.endswith((".sha256", ".txt")):
        return "text/plain"
    return "application/octet-stream"


def _prepare_asset(
    path: Path,
    *,
    preserve_exact: bool = False,
    require_unchanged: bool = False,
) -> PreparedAsset:
    original = path.read_bytes()
    if not original:
        raise ValueError(f"EVIDENCE_ASSET_EMPTY: {path}")
    if preserve_exact:
        return PreparedAsset(
            content=original,
            media_type="application/octet-stream",
            sha256=hashlib.sha256(original).hexdigest(),
            size_bytes=len(original),
        )
    media_type = _declared_media_type(path)
    # The Artifact API normalizes safe textual formats before hashing. Running the
    # same public sanitizer here makes the receipt bind the persisted bytes.
    sanitized = ArtifactContentSanitizer().sanitize(original, media_type)
    if require_unchanged and sanitized.content != original:
        raise ValueError("EVIDENCE_SIGNED_ASSET_NOT_CANONICAL")
    return PreparedAsset(
        content=sanitized.content,
        media_type=media_type,
        sha256=sanitized.sanitized_sha256,
        size_bytes=len(sanitized.content),
    )


def _timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"EVIDENCE_ARTIFACT_TIMESTAMP_INVALID: {field}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"EVIDENCE_ARTIFACT_TIMESTAMP_INVALID: {field}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"EVIDENCE_ARTIFACT_TIMESTAMP_TIMEZONE_REQUIRED: {field}")
    return parsed.astimezone(UTC)


def _request_json(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    expected_status: int,
    **kwargs: Any,
) -> JsonObject:
    response = client.request(method, url, **kwargs)
    if response.status_code != expected_status:
        raise ValueError(
            f"EVIDENCE_ARTIFACT_HTTP_FAILED: {method} {url} returned {response.status_code}"
        )
    try:
        value = response.json()
    except json.JSONDecodeError as exc:
        raise ValueError(f"EVIDENCE_ARTIFACT_RESPONSE_INVALID: {method} {url}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"EVIDENCE_ARTIFACT_RESPONSE_OBJECT_REQUIRED: {method} {url}")
    return value


def _validate_metadata(
    metadata: Mapping[str, Any],
    *,
    expected_digest: str,
    expected_size: int,
    expected_release_id: str,
    expected_git_sha: str,
    expected_image_digest: str,
    minimum_retention_days: int,
    minimum_retain_until: datetime,
) -> tuple[str, datetime, datetime, str]:
    try:
        artifact_id = str(UUID(str(metadata.get("artifact_id", ""))))
    except ValueError as exc:
        raise ValueError("EVIDENCE_ARTIFACT_ID_INVALID") from exc
    if metadata.get("sha256") != expected_digest:
        raise ValueError("EVIDENCE_ARTIFACT_SHA256_MISMATCH")
    if metadata.get("size_bytes") != expected_size:
        raise ValueError("EVIDENCE_ARTIFACT_SIZE_MISMATCH")
    if metadata.get("classification") != "restricted":
        raise ValueError("EVIDENCE_ARTIFACT_CLASSIFICATION_MISMATCH")
    if metadata.get("scan_status") != "malware_clean":
        raise ValueError("EVIDENCE_ARTIFACT_MALWARE_GATE_FAILED")
    version_id = metadata.get("object_version_id")
    if not isinstance(version_id, str) or not version_id.strip():
        raise ValueError("EVIDENCE_ARTIFACT_VERSION_ID_REQUIRED")
    scan_provenance = metadata.get("scan_provenance")
    release_binding = (
        scan_provenance.get("release_binding") if isinstance(scan_provenance, Mapping) else None
    )
    expected_binding = {
        "release_id": expected_release_id,
        "git_sha": expected_git_sha,
        "image_digest": expected_image_digest,
    }
    if release_binding != expected_binding:
        raise ValueError("EVIDENCE_ARTIFACT_RELEASE_BINDING_MISMATCH")
    raw_retention_policy = metadata.get("retention_policy")
    if not isinstance(raw_retention_policy, str):
        raise ValueError("EVIDENCE_ARTIFACT_RETENTION_POLICY_INVALID")
    retention_policy = raw_retention_policy
    retention_match = re.fullmatch(
        r"release-evidence@1:immutable:([0-9]{3,4})d",
        retention_policy,
    )
    if retention_match is None:
        raise ValueError("EVIDENCE_ARTIFACT_RETENTION_POLICY_INVALID")
    if int(retention_match.group(1)) < minimum_retention_days:
        raise ValueError("EVIDENCE_ARTIFACT_RETENTION_POLICY_TOO_SHORT")
    retain_until = _timestamp(
        metadata.get("object_retain_until"),
        field="object_retain_until",
    )
    expires_at = _timestamp(metadata.get("expires_at"), field="expires_at")
    if retain_until < minimum_retain_until:
        raise ValueError("EVIDENCE_ARTIFACT_RETENTION_TOO_SHORT")
    if expires_at < minimum_retain_until:
        raise ValueError("EVIDENCE_ARTIFACT_EXPIRY_TOO_SOON")
    if metadata.get("legal_hold_status") not in {"none", "on"}:
        raise ValueError("EVIDENCE_ARTIFACT_LEGAL_HOLD_STATUS_INVALID")
    return artifact_id, retain_until, expires_at, retention_policy


def _validate_digest_headers(response: httpx.Response, expected_digest: str) -> None:
    if response.headers.get("etag") != f'"sha256:{expected_digest}"':
        raise ValueError("EVIDENCE_ARTIFACT_ETAG_MISMATCH")
    if response.headers.get("digest") != f"sha-256={expected_digest}":
        raise ValueError("EVIDENCE_ARTIFACT_DIGEST_HEADER_MISMATCH")


def _read_and_verify_content(
    response: httpx.Response,
    *,
    expected_digest: str,
    expected_size: int,
    output_path: Path | None,
) -> None:
    if output_path is not None and output_path.exists():
        raise ValueError(f"EVIDENCE_READBACK_OUTPUT_EXISTS: {output_path}")
    destination = output_path.open("xb") if output_path is not None else None
    digest = hashlib.sha256()
    size_bytes = 0
    verified = False
    try:
        for chunk in response.iter_bytes(_CHUNK_BYTES):
            digest.update(chunk)
            size_bytes += len(chunk)
            if destination is not None:
                destination.write(chunk)
        if digest.hexdigest() != expected_digest:
            raise ValueError("EVIDENCE_ARTIFACT_READBACK_SHA256_MISMATCH")
        if size_bytes != expected_size:
            raise ValueError("EVIDENCE_ARTIFACT_READBACK_SIZE_MISMATCH")
        verified = True
    finally:
        if destination is not None:
            destination.close()
        if output_path is not None and not verified:
            output_path.unlink(missing_ok=True)


def _verify_content_readback(
    client: httpx.Client,
    *,
    content_uri: str,
    expected_digest: str,
    expected_size: int,
    output_path: Path | None,
) -> None:
    initial = client.send(client.build_request("GET", content_uri), stream=True)
    try:
        if initial.status_code == 200:
            _validate_digest_headers(initial, expected_digest)
            _read_and_verify_content(
                initial,
                expected_digest=expected_digest,
                expected_size=expected_size,
                output_path=output_path,
            )
            return
        if initial.status_code != 307:
            raise ValueError(
                "EVIDENCE_ARTIFACT_READBACK_FAILED: "
                f"GET {content_uri} returned {initial.status_code}"
            )
        _validate_digest_headers(initial, expected_digest)
        location = initial.headers.get("location", "")
        parsed_location = urlsplit(location)
        if (
            parsed_location.scheme != "https"
            or not parsed_location.netloc
            or parsed_location.username is not None
            or parsed_location.password is not None
            or location == content_uri
        ):
            raise ValueError("EVIDENCE_ARTIFACT_REDIRECT_INVALID")
    finally:
        initial.close()

    # Build a raw request so the API bearer token and cookies are never copied to
    # the separately signed object-store URL.
    redirected = client.send(httpx.Request("GET", location), stream=True)
    try:
        if redirected.status_code != 200:
            raise ValueError(
                "EVIDENCE_ARTIFACT_READBACK_FAILED: "
                f"presigned GET returned {redirected.status_code}"
            )
        _read_and_verify_content(
            redirected,
            expected_digest=expected_digest,
            expected_size=expected_size,
            output_path=output_path,
        )
    finally:
        redirected.close()


def publish_assets(
    *,
    client: httpx.Client,
    base_url: str,
    release_id: str,
    git_sha: str,
    image_digest: str,
    assets: Mapping[str, Path],
    kind: str,
    minimum_retention_days: int,
    readback_dir: Path | None = None,
    now: datetime | None = None,
) -> JsonObject:
    parsed_base_url = urlsplit(base_url)
    if (
        parsed_base_url.scheme != "https"
        or not parsed_base_url.netloc
        or parsed_base_url.username is not None
        or parsed_base_url.password is not None
    ):
        raise ValueError("EVIDENCE_ARTIFACT_BASE_URL_INVALID")
    if not kind.strip() or len(kind) > 100:
        raise ValueError("EVIDENCE_ARTIFACT_KIND_INVALID")
    if minimum_retention_days < 365 or minimum_retention_days > 3_650:
        raise ValueError("EVIDENCE_ARTIFACT_RETENTION_POLICY_INVALID")
    published_at = (now or datetime.now(UTC)).astimezone(UTC)
    minimum_retain_until = published_at + timedelta(days=minimum_retention_days)
    base = base_url.rstrip("/")
    resolved_readback_dir = readback_dir.resolve() if readback_dir is not None else None
    if resolved_readback_dir is not None:
        resolved_readback_dir.mkdir(parents=True, exist_ok=True)
    published_assets: dict[str, JsonObject] = {}

    for name, raw_path in sorted(assets.items()):
        path = raw_path.resolve()
        prepared = _prepare_asset(
            path,
            preserve_exact=(
                kind == "release-evidence-component" and name in _SIGNED_OPAQUE_COMPONENT_ASSETS
            ),
            require_unchanged=kind == "release-evidence" and name == "release_evidence",
        )
        metadata = _request_json(
            client,
            "POST",
            f"{base}/v1/artifacts",
            expected_status=201,
            params={
                "kind": kind,
                "classification": "restricted",
            },
            headers={
                "Content-Type": prepared.media_type,
                "Content-Length": str(prepared.size_bytes),
                "X-Evidence-Release-ID": release_id,
                "X-Evidence-Git-SHA": git_sha,
                "X-Evidence-Image-Digest": image_digest,
            },
            content=prepared.content,
        )
        artifact_id, retain_until, expires_at, retention_policy = _validate_metadata(
            metadata,
            expected_digest=prepared.sha256,
            expected_size=prepared.size_bytes,
            expected_release_id=release_id,
            expected_git_sha=git_sha,
            expected_image_digest=image_digest,
            minimum_retention_days=minimum_retention_days,
            minimum_retain_until=minimum_retain_until,
        )
        content_uri = f"{base}/v1/artifacts/{artifact_id}/content/sha256:{prepared.sha256}"
        _verify_content_readback(
            client,
            content_uri=content_uri,
            expected_digest=prepared.sha256,
            expected_size=prepared.size_bytes,
            output_path=(
                resolved_readback_dir / name if resolved_readback_dir is not None else None
            ),
        )
        published_assets[name] = {
            "artifact_id": artifact_id,
            "content_uri": content_uri,
            "sha256": f"sha256:{prepared.sha256}",
            "size_bytes": prepared.size_bytes,
            "classification": "restricted",
            "release_binding": {
                "release_id": release_id,
                "git_sha": git_sha,
                "image_digest": image_digest,
            },
            "retention_policy": retention_policy,
            "scan_status": "malware_clean",
            "object_version_id": metadata["object_version_id"],
            "object_retain_until": retain_until.isoformat(),
            "legal_hold_status": metadata["legal_hold_status"],
            "expires_at": expires_at.isoformat(),
            "readback_verified": True,
        }

    receipt: JsonObject = {
        "schema_version": "1.0",
        "kind": kind,
        "release_id": release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "assets": published_assets,
        "published_at": published_at.isoformat(),
        "verified": True,
    }
    Draft202012Validator(
        _load_object(PUBLICATION_SCHEMA),
        format_checker=FormatChecker(),
    ).validate(receipt)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish release evidence files to restricted, immutable, "
            "digest-addressed Artifact storage"
        )
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--asset", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument(
        "--kind",
        choices=["release-evidence", "release-evidence-component"],
        required=True,
    )
    parser.add_argument("--minimum-retention-days", type=int, default=365)
    parser.add_argument("--readback-dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    token = os.environ.get(args.token_env, "")
    if not token:
        print(
            f"evidence publication failed: token env {args.token_env!r} is empty",
            file=sys.stderr,
        )
        return 2
    try:
        assets = _parse_asset_specs(args.asset)
        with httpx.Client(
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(60.0),
            follow_redirects=False,
        ) as client:
            receipt = publish_assets(
                client=client,
                base_url=args.base_url,
                release_id=args.release_id,
                git_sha=args.git_sha,
                image_digest=args.image_digest,
                assets=assets,
                kind=args.kind,
                minimum_retention_days=args.minimum_retention_days,
                readback_dir=args.readback_dir,
            )
    except (
        OSError,
        ValueError,
        httpx.HTTPError,
        json.JSONDecodeError,
        PlatformError,
    ) as exc:
        print(f"evidence publication failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
