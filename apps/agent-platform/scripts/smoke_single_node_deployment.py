from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4

TERMINAL_FAILURE_STATES = {
    "budget_exceeded",
    "cancelled",
    "failed",
    "paused",
    "rejected",
    "timed_out",
    "waiting_approval",
}

_ACCESS_TOKEN = ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a constrained single-node Agent Platform deployment through "
            "health, readiness, run completion, and event readback."
        )
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:5181")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--expected-git-sha", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument(
        "--expect-structural-only-readiness-block",
        action="store_true",
    )
    args = parser.parse_args()
    global _ACCESS_TOKEN
    _ACCESS_TOKEN = os.environ.get("AGENT_DEVELOPMENT_CONSOLE_TOKEN", "").strip()

    base_url = args.base_url.rstrip("/")
    health = _request_json("GET", f"{base_url}/health")
    if health.get("ok") is not True:
        raise RuntimeError(f"health response is not healthy: {health!r}")
    if health.get("release_git_sha") != args.expected_git_sha:
        raise RuntimeError(f"release Git SHA mismatch: {health!r}")
    if health.get("release_image_digest") != args.expected_image_digest:
        raise RuntimeError(f"release image digest mismatch: {health!r}")

    ready_status = 503 if args.expect_structural_only_readiness_block else 200
    ready = _request_json("GET", f"{base_url}/ready", expected_status=ready_status)
    if args.expect_structural_only_readiness_block:
        _assert_known_structural_only_readiness_block(ready)
    elif ready != {"ready": True}:
        raise RuntimeError(f"readiness response is not ready: {ready!r}")

    smoke_id = uuid4().hex
    accepted = _request_json(
        "POST",
        f"{base_url}/v1/runs",
        headers={
            "Idempotency-Key": f"single-node-smoke-{smoke_id}",
            "X-Correlation-ID": f"single-node-smoke-{smoke_id}",
        },
        payload=_run_payload(),
        expected_status=202,
    )
    run_id = str(accepted.get("run_id", "")).strip()
    if not run_id:
        raise RuntimeError(f"run acceptance omitted run_id: {accepted!r}")

    deadline = time.monotonic() + args.timeout_seconds
    snapshot: dict[str, Any] = {}
    while time.monotonic() < deadline:
        snapshot = _request_json("GET", f"{base_url}/v1/runs/{run_id}")
        status = str(snapshot.get("status", ""))
        if status == "completed":
            break
        if status in TERMINAL_FAILURE_STATES:
            raise RuntimeError(f"smoke run reached terminal failure {status}: {snapshot!r}")
        time.sleep(1)
    else:
        raise RuntimeError(
            f"smoke run {run_id} did not complete in {args.timeout_seconds} seconds; "
            f"last snapshot={snapshot!r}"
        )

    artifact_readback = _read_back_artifact(base_url, run_id, snapshot)
    events = _request_text("GET", f"{base_url}/v1/runs/{run_id}/events")
    if "run.completed" not in events:
        raise RuntimeError(f"run {run_id} event readback omitted run.completed")

    print(
        json.dumps(
            {
                "schema_version": "1.0",
                "profile": "single-node-dev-validation",
                "health": True,
                "ready": not args.expect_structural_only_readiness_block,
                "readiness_status": (
                    "known_constrained_readiness_block"
                    if args.expect_structural_only_readiness_block
                    else "ready"
                ),
                "run_id": run_id,
                "run_status": snapshot["status"],
                **artifact_readback,
                "completed_event_readback": True,
            },
            sort_keys=True,
        )
    )
    return 0


def _read_back_artifact(
    base_url: str,
    run_id: str,
    snapshot: dict[str, Any],
) -> dict[str, object]:
    result = snapshot.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"completed smoke run {run_id} omitted its result")
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimeError(f"completed smoke run {run_id} omitted Artifact references")
    artifact_ref = artifacts[0]
    if not isinstance(artifact_ref, dict):
        raise RuntimeError(f"smoke run {run_id} returned an invalid Artifact reference")

    artifact_id = artifact_ref.get("artifact_id")
    expected_sha256 = artifact_ref.get("sha256")
    expected_size = artifact_ref.get("size_bytes")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise RuntimeError(f"smoke run {run_id} Artifact reference omitted artifact_id")
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise RuntimeError(f"smoke run {run_id} Artifact reference has an invalid SHA-256")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise RuntimeError(f"smoke run {run_id} Artifact reference has an invalid size")

    metadata = _request_json("GET", f"{base_url}/v1/artifacts/{artifact_id}")
    expected_metadata = {
        "artifact_id": artifact_id,
        "run_id": run_id,
        "sha256": expected_sha256,
        "size_bytes": expected_size,
    }
    mismatches = {
        name: {"expected": expected, "actual": metadata.get(name)}
        for name, expected in expected_metadata.items()
        if metadata.get(name) != expected
    }
    if mismatches:
        raise RuntimeError(
            f"smoke run {run_id} Artifact metadata readback mismatch: {mismatches!r}"
        )

    content = _request_bytes(
        "GET",
        f"{base_url}/v1/artifacts/{artifact_id}?download=true&purpose=single-node-release-smoke",
    )
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if len(content) != expected_size or actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"smoke run {run_id} Artifact content readback mismatch: "
            f"expected size={expected_size} sha256={expected_sha256}, "
            f"got size={len(content)} sha256={actual_sha256}"
        )
    return {
        "artifact_readback": True,
        "artifact_id": artifact_id,
        "artifact_sha256": actual_sha256,
        "artifact_size_bytes": len(content),
    }


def _assert_known_structural_only_readiness_block(ready: dict[str, Any]) -> None:
    dependencies = ready.get("dependencies")
    if ready.get("ready") is not False or not isinstance(dependencies, dict):
        raise RuntimeError(f"invalid constrained readiness response: {ready!r}")
    non_ok = {name: status for name, status in dependencies.items() if status != "ok"}
    expected = {"artifact_malware_scanner": "error:policy-fail-closed:structural-only"}
    if non_ok != expected:
        raise RuntimeError(
            f"readiness has an unexpected dependency failure: expected {expected!r}, got {non_ok!r}"
        )


def _run_payload() -> dict[str, object]:
    return {
        "goal": "Compare SG and JP with source-backed conclusions",
        "success_criteria": [
            {
                "id": "sc-1",
                "description": "Every key claim cites evidence",
                "severity": "must",
                "verification": "evidence",
            }
        ],
        "allowed_capabilities": ["knowledge.search", "artifact.create"],
        "constraints": {"markets": ["SG", "JP"]},
        "budget": {
            "max_cost_usd": "5.00",
            "max_duration_seconds": 120,
            "max_tool_calls": 10,
        },
        "external_write_policy": "deny",
        "requested_output": {"format": "market_report@1.0"},
    }


def _request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
    expected_status: int = 200,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request_headers = dict(headers or {})
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    response_body, status = _request(method, url, request_headers, body)
    if status != expected_status:
        raise RuntimeError(
            f"{method} {url} returned {status}, expected {expected_status}: "
            f"{response_body.decode('utf-8', errors='replace')}"
        )
    try:
        value = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{method} {url} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{method} {url} returned non-object JSON")
    return value


def _request_text(method: str, url: str) -> str:
    response_body, status = _request(method, url, {}, None)
    if status != 200:
        raise RuntimeError(
            f"{method} {url} returned {status}: {response_body.decode('utf-8', errors='replace')}"
        )
    return response_body.decode("utf-8")


def _request_bytes(method: str, url: str) -> bytes:
    response_body, status = _request(method, url, {}, None)
    if status != 200:
        raise RuntimeError(
            f"{method} {url} returned {status}: {response_body.decode('utf-8', errors='replace')}"
        )
    return response_body


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> tuple[bytes, int]:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError(f"single-node smoke only permits loopback HTTP targets: {url}")
    request_headers = dict(headers)
    if _ACCESS_TOKEN:
        request_headers.setdefault("Authorization", f"Bearer {_ACCESS_TOKEN}")
    request = Request(  # noqa: S310 - scheme and host are constrained above
        url,
        data=body,
        headers=request_headers,
        method=method,
    )
    try:
        with urlopen(  # noqa: S310 - scheme and host are constrained above
            request,
            timeout=15,
        ) as response:
            return response.read(), response.status
    except HTTPError as exc:
        return exc.read(), exc.code
    except URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
