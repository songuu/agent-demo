"""Verify the exact deployed Agent Platform release and a read-only smoke run."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _request_json(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    expected_status: int,
    **kwargs: Any,
) -> dict[str, Any]:
    response = client.request(method, path, **kwargs)
    if response.status_code != expected_status:
        body = response.text[:1_000]
        raise RuntimeError(
            f"{method} {path} returned {response.status_code}, expected {expected_status}: {body}"
        )
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError(f"{method} {path} did not return a JSON object")
    return value


def _verify_health(
    client: httpx.Client,
    *,
    expected_git_sha: str,
    expected_image_digest: str,
    expected_tool_catalog_id: str,
    expected_tool_catalog_digest: str,
) -> dict[str, Any]:
    health = _request_json(client, "GET", "/health", expected_status=200)
    ready = _request_json(client, "GET", "/ready", expected_status=200)
    if health.get("ok") is not True or ready.get("ready") is not True:
        raise RuntimeError("DEPLOYMENT_NOT_READY")
    if health.get("release_git_sha") != expected_git_sha:
        raise RuntimeError(
            "RELEASE_GIT_SHA_MISMATCH: "
            f"expected {expected_git_sha}, got {health.get('release_git_sha')}"
        )
    if health.get("release_image_digest") != expected_image_digest:
        raise RuntimeError(
            "RELEASE_IMAGE_DIGEST_MISMATCH: "
            f"expected {expected_image_digest}, got {health.get('release_image_digest')}"
        )
    release_identity = health.get("release_identity")
    if not isinstance(release_identity, dict):
        raise RuntimeError("RELEASE_IDENTITY_MISSING")
    if release_identity.get("tool_catalog_id") != expected_tool_catalog_id:
        raise RuntimeError(
            "TOOL_CATALOG_ID_MISMATCH: "
            f"expected {expected_tool_catalog_id}, "
            f"got {release_identity.get('tool_catalog_id')}"
        )
    if release_identity.get("tool_catalog_digest") != expected_tool_catalog_digest:
        raise RuntimeError(
            "TOOL_CATALOG_DIGEST_MISMATCH: "
            f"expected {expected_tool_catalog_digest}, "
            f"got {release_identity.get('tool_catalog_digest')}"
        )
    dependencies = health.get("dependencies")
    if not isinstance(dependencies, dict) or not dependencies:
        raise RuntimeError("HEALTH_DEPENDENCIES_MISSING")
    unhealthy = {str(name): str(status) for name, status in dependencies.items() if status != "ok"}
    if unhealthy:
        raise RuntimeError(f"DEPENDENCY_HEALTH_FAILED: {unhealthy}")
    return health


def _smoke_run(
    client: httpx.Client,
    *,
    token: str,
    expected_git_sha: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": f"release-smoke-{expected_git_sha}",
        "X-Correlation-ID": f"release-{expected_git_sha[:16]}",
        "Content-Type": "application/json",
    }
    payload = {
        "goal": "Produce a source-backed release smoke summary for SG and JP.",
        "success_criteria": [
            {
                "id": "release-smoke-evidence",
                "description": "Every material claim is linked to approved evidence.",
                "severity": "must",
                "verification": "evidence",
            }
        ],
        "allowed_capabilities": ["knowledge.search", "artifact.create"],
        "constraints": {
            "markets": ["SG", "JP"],
            "use_case": "release-smoke",
        },
        "budget": {
            "max_cost_usd": "1.000000",
            "max_duration_seconds": min(timeout_seconds, 600),
            "max_tool_calls": 12,
        },
        "external_write_policy": "deny",
        "requested_output": {"format": "market_report@1.0"},
    }
    accepted = _request_json(
        client,
        "POST",
        "/v1/runs",
        expected_status=202,
        headers=headers,
        json=payload,
    )
    run_id = accepted.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise RuntimeError("RELEASE_SMOKE_RUN_ID_MISSING")

    deadline = time.monotonic() + timeout_seconds
    while True:
        snapshot = _request_json(
            client,
            "GET",
            f"/v1/runs/{run_id}",
            expected_status=200,
            headers={"Authorization": f"Bearer {token}"},
        )
        status = str(snapshot.get("status", ""))
        if status in TERMINAL_STATUSES:
            if status != "completed":
                raise RuntimeError(f"RELEASE_SMOKE_RUN_FAILED: run_id={run_id}, status={status}")
            if snapshot.get("result") is None:
                raise RuntimeError(f"RELEASE_SMOKE_RESULT_MISSING: run_id={run_id}")
            return snapshot
        if time.monotonic() >= deadline:
            raise RuntimeError(f"RELEASE_SMOKE_TIMEOUT: run_id={run_id}, last_status={status}")
        time.sleep(2)


def verify_release(args: argparse.Namespace) -> dict[str, Any]:
    token = args.token or os.environ.get("AGENT_PLATFORM_RELEASE_TOKEN", "")
    if not args.skip_smoke and not token:
        raise RuntimeError("AGENT_PLATFORM_RELEASE_TOKEN is required for the read-only smoke run")

    with httpx.Client(
        base_url=args.base_url.rstrip("/"),
        timeout=httpx.Timeout(args.request_timeout_seconds),
        follow_redirects=False,
        verify=not args.insecure,
    ) as client:
        health = _verify_health(
            client,
            expected_git_sha=args.expected_git_sha,
            expected_image_digest=args.expected_image_digest,
            expected_tool_catalog_id=args.expected_tool_catalog_id,
            expected_tool_catalog_digest=args.expected_tool_catalog_digest,
        )
        smoke = (
            None
            if args.skip_smoke
            else _smoke_run(
                client,
                token=token,
                expected_git_sha=args.expected_git_sha,
                timeout_seconds=args.smoke_timeout_seconds,
            )
        )
    return {
        "schema_version": "1.0",
        "verified_at": datetime.now(UTC).isoformat(),
        "base_url": args.base_url,
        "release_git_sha": args.expected_git_sha,
        "release_image_digest": args.expected_image_digest,
        "tool_catalog_id": args.expected_tool_catalog_id,
        "tool_catalog_digest": args.expected_tool_catalog_digest,
        "dependencies": health["dependencies"],
        "smoke_run_id": None if smoke is None else smoke["run_id"],
        "smoke_status": "skipped" if smoke is None else smoke["status"],
        "verified": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify Agent Platform release identity, readiness, and smoke flow"
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-tool-catalog-id", required=True)
    parser.add_argument("--expected-tool-catalog-digest", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--request-timeout-seconds", type=int, default=15)
    parser.add_argument("--smoke-timeout-seconds", type=int, default=600)
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        report = verify_release(args)
    except (RuntimeError, httpx.HTTPError, ValueError) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
