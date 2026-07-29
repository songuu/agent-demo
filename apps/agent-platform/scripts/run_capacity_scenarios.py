"""Run the architecture capacity scenarios against an isolated staging tenant.

The runner performs real HTTP requests and emits a machine-readable report. It
does not provision test data, change quotas, or enable faults: those are
explicit staging-operator gates so a load test cannot silently mutate
production controls.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import statistics
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

import httpx
from jsonschema import Draft202012Validator, FormatChecker

CONTROLLED_ADMISSION_CODES = {
    "BACKPRESSURE_REJECTED",
    "RUN_QUEUE_BACKPRESSURE",
    "RUN_QUEUE_HARD_LIMIT",
    "TENANT_BUDGET_BACKPRESSURE",
    "TENANT_BUDGET_EXHAUSTED",
    "TENANT_CONCURRENCY_EXHAUSTED",
}
MIB = 1024 * 1024
MAX_SERVER_REQUEST_CHUNK_BYTES = 8 * MIB
REQUIRED_SCENARIOS = frozenset(
    {"burst", "long_runs", "tool_latency", "persistent_429", "artifacts", "approvals"}
)
RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PAYLOAD_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
CONTROL_EVIDENCE_SCHEMA_PATH = (
    Path(__file__).parents[1] / "deploy" / "ci" / "pending-approval-control-evidence.schema.json"
)


class _NonFiniteJsonError(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise _NonFiniteJsonError(f"non-finite JSON constant: {value}")


def _strict_json_loads(payload: str | bytes) -> Any:
    return json.loads(payload, parse_constant=_reject_json_constant)


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _validated_release_identity(
    release_id: str,
    git_sha: str,
    image_digest: str,
) -> tuple[str, str, str]:
    if RELEASE_ID_PATTERN.fullmatch(release_id) is None:
        raise ValueError("CAPACITY_RELEASE_ID_INVALID")
    if GIT_SHA_PATTERN.fullmatch(git_sha) is None:
        raise ValueError("CAPACITY_GIT_SHA_INVALID")
    if IMAGE_DIGEST_PATTERN.fullmatch(image_digest) is None:
        raise ValueError("CAPACITY_IMAGE_DIGEST_INVALID")
    return release_id, git_sha, image_digest


@dataclass(frozen=True, slots=True)
class Sample:
    status: int
    latency_seconds: float
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    name: str
    passed: bool
    requests: int
    statuses: dict[str, int]
    p95_seconds: float
    evidence: dict[str, Any]


class RepeatingBytes(httpx.AsyncByteStream):
    """Generate an exact request size without constructing the body in memory."""

    def __init__(self, size_bytes: int, *, chunk_bytes: int = MIB) -> None:
        if size_bytes < 1 or chunk_bytes < 1:
            raise ValueError("STREAM_SIZE_INVALID")
        self._size_bytes = size_bytes
        self._chunk_bytes = min(chunk_bytes, size_bytes)

    async def __aiter__(self) -> AsyncIterator[bytes]:
        remaining = self._size_bytes
        chunk = b"\0" * self._chunk_bytes
        while remaining:
            emitted = min(remaining, len(chunk))
            yield chunk[:emitted]
            remaining -= emitted


def _p95(samples: list[Sample]) -> float:
    if not samples:
        return 0.0
    ordered = sorted(sample.latency_seconds for sample in samples)
    return ordered[max(math.ceil(len(ordered) * 0.95) - 1, 0)]


def _summarize(
    name: str,
    samples: list[Sample],
    *,
    passed: bool,
    evidence: dict[str, Any],
) -> ScenarioResult:
    statuses: dict[str, int] = {}
    for sample in samples:
        key = str(sample.status)
        statuses[key] = statuses.get(key, 0) + 1
    return ScenarioResult(
        name=name,
        passed=passed,
        requests=len(samples),
        statuses=statuses,
        p95_seconds=round(_p95(samples), 6),
        evidence=evidence,
    )


def _run_body(*, long_running: bool) -> dict[str, Any]:
    return {
        "goal": (
            "Execute a controlled long-running capacity probe"
            if long_running
            else "Execute a controlled burst capacity probe"
        ),
        "success_criteria": [
            {
                "id": "capacity-criterion",
                "description": "The staging capacity probe terminates with auditable evidence.",
                "severity": "must",
                "verification": "deterministic",
            }
        ],
        "allowed_capabilities": ["knowledge.search"],
        "constraints": {
            "use_case": "capacity-validation",
            "priority": "low" if not long_running else "normal",
            "capacity_probe": True,
        },
        "budget": {
            "max_cost_usd": "1.000000",
            "max_duration_seconds": 3600 if long_running else 300,
            "max_tool_calls": 3,
        },
        "external_write_policy": "deny",
        "requested_output": {"format": "report@1.0"},
    }


def _error_code(response: httpx.Response) -> str | None:
    try:
        body = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    error = body.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return str(code) if isinstance(code, str) else None


async def _request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    **kwargs: Any,
) -> Sample:
    started = time.monotonic()
    response = await client.request(method, path, **kwargs)
    return Sample(
        status=response.status_code,
        latency_seconds=max(time.monotonic() - started, 0.0),
        error_code=_error_code(response),
    )


async def _bounded(
    factories: Sequence[Callable[[], Awaitable[Sample]]],
    *,
    concurrency: int,
) -> list[Sample]:
    semaphore = asyncio.Semaphore(concurrency)

    async def run(factory: Callable[[], Awaitable[Sample]]) -> Sample:
        async with semaphore:
            return await factory()

    return await asyncio.gather(*(run(factory) for factory in factories))


def _controlled_admission(sample: Sample) -> bool:
    return sample.status in {202, 429} or (
        sample.status == 503 and sample.error_code in CONTROLLED_ADMISSION_CODES
    )


def _require_complete_scenario_set(selected: set[str]) -> None:
    if selected != REQUIRED_SCENARIOS:
        raise ValueError(
            "CAPACITY_SCENARIO_SET_INCOMPLETE:"
            f"required={sorted(REQUIRED_SCENARIOS)}:actual={sorted(selected)}"
        )


def _long_run_passed(samples: list[Sample]) -> bool:
    return len(samples) == 100 and all(sample.status == 202 for sample in samples)


def _artifact_streaming_observation(
    body: object,
    *,
    expected_size: int,
    expected_sha256: str,
) -> tuple[bool, dict[str, Any]]:
    document = body if isinstance(body, dict) else {}
    raw_provenance = document.get("scan_provenance")
    provenance = raw_provenance if isinstance(raw_provenance, dict) else {}
    raw_transport = provenance.get("transport")
    transport = raw_transport if isinstance(raw_transport, dict) else {}
    chunk_count = transport.get("chunk_count")
    max_chunk_bytes = transport.get("max_request_chunk_bytes")
    valid_chunk_count = type(chunk_count) is int and chunk_count >= 2
    valid_max_chunk = (
        type(max_chunk_bytes) is int
        and 0 < max_chunk_bytes <= MAX_SERVER_REQUEST_CHUNK_BYTES
        and max_chunk_bytes < expected_size
    )
    passed = (
        document.get("size_bytes") == expected_size
        and document.get("sha256") == expected_sha256
        and document.get("scan_status") == "malware_clean"
        and isinstance(document.get("object_version_id"), str)
        and bool(document.get("object_version_id"))
        and transport.get("mode") == "request-stream-to-file"
        and transport.get("request_size_bytes") == expected_size
        and transport.get("request_sha256") == expected_sha256
        and valid_chunk_count
        and valid_max_chunk
    )
    return passed, {
        "artifact_id": document.get("artifact_id"),
        "size_bytes": document.get("size_bytes"),
        "sha256": document.get("sha256"),
        "scan_status": document.get("scan_status"),
        "object_version_id": document.get("object_version_id"),
        "server_transport": {
            "mode": transport.get("mode"),
            "request_size_bytes": transport.get("request_size_bytes"),
            "request_sha256": transport.get("request_sha256"),
            "chunk_count": chunk_count,
            "max_request_chunk_bytes": max_chunk_bytes,
        },
        "passed": passed,
    }


def _zero_payload_sha256(size_bytes: int) -> str:
    digest = hashlib.sha256()
    chunk = b"\0" * MIB
    remaining = size_bytes
    while remaining:
        emitted = min(remaining, len(chunk))
        digest.update(chunk[:emitted])
        remaining -= emitted
    return digest.hexdigest()


async def burst_runs(
    client: httpx.AsyncClient,
    *,
    baseline_rps: float,
    duration_seconds: int,
) -> ScenarioResult:
    rate = baseline_rps * 10
    count = max(math.ceil(rate * duration_seconds), 1)
    semaphore = asyncio.Semaphore(max(math.ceil(rate * 2), 10))
    started = time.monotonic()

    async def launch(index: int) -> Sample:
        target = started + (index / rate)
        await asyncio.sleep(max(target - time.monotonic(), 0.0))
        async with semaphore:
            return await _request(
                client,
                "POST",
                "/v1/runs",
                headers={"Idempotency-Key": f"capacity-burst-{uuid4()}"},
                json=_run_body(long_running=False),
            )

    samples = await asyncio.gather(*(launch(index) for index in range(count)))
    passed = all(_controlled_admission(sample) for sample in samples)
    return _summarize(
        "ten_x_burst_one_minute",
        samples,
        passed=passed,
        evidence={
            "baseline_rps": baseline_rps,
            "offered_rps": rate,
            "duration_seconds": duration_seconds,
            "controlled_admission_responses": sum(
                _controlled_admission(sample) for sample in samples
            ),
        },
    )


async def long_runs(client: httpx.AsyncClient) -> ScenarioResult:
    factories = [
        lambda: _request(
            client,
            "POST",
            "/v1/runs",
            headers={"Idempotency-Key": f"capacity-long-{uuid4()}"},
            json=_run_body(long_running=True),
        )
        for _ in range(100)
    ]
    samples = await _bounded(factories, concurrency=100)
    return _summarize(
        "one_hundred_concurrent_long_runs",
        samples,
        passed=_long_run_passed(samples),
        evidence={
            "concurrency": 100,
            "max_duration_seconds": 3600,
            "accepted_runs": sum(sample.status == 202 for sample in samples),
        },
    )


async def tool_latency(
    client: httpx.AsyncClient,
    *,
    baseline_path: str,
    degraded_path: str,
    sample_count: int,
) -> ScenarioResult:
    baseline = await _bounded(
        [lambda: _request(client, "GET", baseline_path) for _ in range(sample_count)],
        concurrency=min(sample_count, 20),
    )
    degraded = await _bounded(
        [lambda: _request(client, "GET", degraded_path) for _ in range(sample_count)],
        concurrency=min(sample_count, 20),
    )
    baseline_p95 = _p95(baseline)
    degraded_p95 = _p95(degraded)
    samples = [*baseline, *degraded]
    passed = (
        baseline_p95 > 0
        and degraded_p95 >= baseline_p95 * 5
        and all(sample.status < 500 for sample in samples)
    )
    return _summarize(
        "tool_p95_five_x",
        samples,
        passed=passed,
        evidence={
            "baseline_p95_seconds": round(baseline_p95, 6),
            "degraded_p95_seconds": round(degraded_p95, 6),
            "observed_multiplier": round(degraded_p95 / baseline_p95, 3) if baseline_p95 else None,
            "operator_gate": "degraded_path must be backed by a controlled 5x staging fault",
        },
    )


async def persistent_429(
    client: httpx.AsyncClient,
    *,
    path: str,
    sample_count: int,
) -> ScenarioResult:
    samples = await _bounded(
        [lambda: _request(client, "GET", path) for _ in range(sample_count)],
        concurrency=min(sample_count, 50),
    )
    return _summarize(
        "persistent_429",
        samples,
        passed=bool(samples) and all(sample.status == 429 for sample in samples),
        evidence={
            "expected_status": 429,
            "operator_gate": "path must use an isolated low-quota staging principal",
        },
    )


async def streaming_artifacts(client: httpx.AsyncClient) -> ScenarioResult:
    samples: list[Sample] = []
    observations: list[dict[str, Any]] = []
    sizes = (50 * MIB, 200 * MIB)
    for size in sizes:
        started = time.monotonic()
        response = await client.request(
            "POST",
            "/v1/artifacts?kind=capacity-probe&classification=internal",
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
            content=RepeatingBytes(size),
        )
        samples.append(
            Sample(
                status=response.status_code,
                latency_seconds=max(time.monotonic() - started, 0.0),
                error_code=_error_code(response),
            )
        )
        try:
            body: object = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        _, observation = _artifact_streaming_observation(
            body,
            expected_size=size,
            expected_sha256=_zero_payload_sha256(size),
        )
        observations.append(observation)
    return _summarize(
        "artifact_streaming_50_to_200_mib",
        samples,
        passed=all(sample.status == 201 for sample in samples)
        and all(observation["passed"] is True for observation in observations),
        evidence={
            "sizes_bytes": list(sizes),
            "client_chunk_bytes": MIB,
            "maximum_server_request_chunk_bytes": MAX_SERVER_REQUEST_CHUNK_BYTES,
            "server_observations": observations,
        },
    )


def _approval_manifest(path: Path) -> list[dict[str, str]]:
    try:
        rows = [
            _strict_json_loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _NonFiniteJsonError) as exc:
        raise ValueError("CAPACITY_APPROVAL_MANIFEST_INVALID") from exc
    if len(rows) < 1000:
        raise ValueError("CAPACITY_APPROVAL_MANIFEST_MUST_CONTAIN_AT_LEAST_1000_ROWS")

    result: list[dict[str, str]] = []
    action_ids: set[str] = set()
    workflow_by_run: dict[str, str] = {}
    required_fields = (
        "action_id",
        "run_id",
        "workflow_id",
        "payload_hash",
        "expires_at",
        "cohort",
    )
    for row in rows:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(field), str) or not str(row[field]).strip()
            for field in required_fields
        ):
            raise ValueError("CAPACITY_APPROVAL_MANIFEST_INVALID")
        action_id = str(row["action_id"]).strip()
        run_id = str(row["run_id"]).strip()
        workflow_id = str(row["workflow_id"]).strip()
        payload_hash = str(row["payload_hash"]).strip()
        expires_at = str(row["expires_at"]).strip()
        cohort = str(row["cohort"]).strip()
        if (
            action_id in action_ids
            or PAYLOAD_HASH_PATTERN.fullmatch(payload_hash) is None
            or _utc_timestamp(expires_at) is None
            or cohort != "pending_backlog"
        ):
            raise ValueError("CAPACITY_APPROVAL_MANIFEST_INVALID")
        previous_workflow_id = workflow_by_run.setdefault(run_id, workflow_id)
        if previous_workflow_id != workflow_id:
            raise ValueError("CAPACITY_APPROVAL_MANIFEST_RUN_WORKFLOW_MISMATCH")
        action_ids.add(action_id)
        result.append(
            {
                "action_id": action_id,
                "run_id": run_id,
                "workflow_id": workflow_id,
                "payload_hash": payload_hash,
                "expires_at": expires_at,
                "cohort": cohort,
            }
        )
    return result


def _request_path(client: httpx.AsyncClient, path: str) -> str:
    if client.base_url.scheme in {"http", "https"}:
        return path
    return f"https://capacity.invalid{path}"


def _raw_json_sha256(raw_json: str) -> str:
    return "sha256:" + hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


def _is_content_addressed_uri(uri: object, digest: object) -> bool:
    if not isinstance(uri, str) or not isinstance(digest, str):
        return False
    try:
        parsed = urlsplit(uri)
        parsed_port = parsed.port
    except ValueError:
        return False
    terminal = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and (parsed_port is None or parsed_port > 0)
        and not parsed.query
        and not parsed.fragment
        and terminal == digest
    )


def _content_addressed_payload(asset: object) -> dict[str, Any] | None:
    if not isinstance(asset, dict):
        return None
    raw_json = asset.get("raw_json")
    digest = asset.get("sha256")
    if (
        not isinstance(raw_json, str)
        or digest != _raw_json_sha256(raw_json)
        or not _is_content_addressed_uri(asset.get("content_uri"), digest)
    ):
        return None
    try:
        payload = _strict_json_loads(raw_json)
    except (json.JSONDecodeError, _NonFiniteJsonError):
        return None
    return payload if isinstance(payload, dict) else None


def _string_set(value: object) -> set[str] | None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return None
    values = set(value)
    return values if len(values) == len(value) else None


def _derive_pending_control_checks(
    document: object,
    *,
    release_id: str,
    git_sha: str,
    image_digest: str,
    manifest_sha256: str,
    action_ids: set[str],
    run_ids: set[str],
    workflow_ids: set[str],
) -> dict[str, bool]:
    result = {
        "notification_delivery_verified": False,
        "expiry_processing_verified": False,
        "resource_leak_free_verified": False,
    }
    root_payload = document if isinstance(document, dict) else None
    if root_payload is None:
        return result
    if (
        root_payload.get("schema_version") != "1.0"
        or root_payload.get("release_id") != release_id
        or root_payload.get("git_sha") != git_sha
        or root_payload.get("image_digest") != image_digest
        or root_payload.get("manifest_sha256") != manifest_sha256
    ):
        return result
    scope = root_payload.get("scope")
    if not isinstance(scope, dict):
        return result
    scoped_action_ids = _string_set(scope.get("action_ids"))
    scoped_run_ids = _string_set(scope.get("run_ids"))
    scoped_workflow_ids = _string_set(scope.get("workflow_ids"))
    expiry_probe_action_ids = _string_set(scope.get("expiry_probe_action_ids"))
    if (
        scoped_action_ids != action_ids
        or scoped_run_ids != run_ids
        or scoped_workflow_ids != workflow_ids
        or not expiry_probe_action_ids
        or not expiry_probe_action_ids.issubset(action_ids)
    ):
        return result

    notification_payload = _content_addressed_payload(root_payload.get("notifications"))
    if notification_payload is not None:
        raw_receipts = notification_payload.get("receipts")
        receipts = raw_receipts if isinstance(raw_receipts, list) else []
        receipt_rows = [receipt for receipt in receipts if isinstance(receipt, dict)]
        delivered_action_ids = {
            str(receipt.get("action_id"))
            for receipt in receipt_rows
            if receipt.get("delivered") is True
        }
        receipt_ids = [receipt.get("receipt_id") for receipt in receipt_rows]
        timestamps_valid = all(
            _utc_timestamp(receipt.get("delivered_at")) is not None for receipt in receipt_rows
        )
        result["notification_delivery_verified"] = (
            len(receipt_rows) == len(receipts) == len(action_ids)
            and delivered_action_ids == action_ids
            and all(isinstance(receipt_id, str) and receipt_id for receipt_id in receipt_ids)
            and len(receipt_ids) == len(set(receipt_ids))
            and timestamps_valid
        )

    expiry_payload = _content_addressed_payload(root_payload.get("expiry"))
    if expiry_payload is not None:
        raw_observations = expiry_payload.get("observations")
        observations = raw_observations if isinstance(raw_observations, list) else []
        observation_rows = [row for row in observations if isinstance(row, dict)]
        observed_expired_ids = {
            str(row.get("action_id"))
            for row in observation_rows
            if row.get("status") == "expired" and _utc_timestamp(row.get("observed_at")) is not None
        }
        result["expiry_processing_verified"] = (
            len(observation_rows) == len(observations) == len(expiry_probe_action_ids)
            and observed_expired_ids == expiry_probe_action_ids
        )

    resource_payload = _content_addressed_payload(root_payload.get("resources"))
    if resource_payload is not None:
        closed_workflow_ids = _string_set(resource_payload.get("closed_workflow_ids"))
        open_workflow_ids = _string_set(resource_payload.get("open_workflow_ids"))
        backlog_before = resource_payload.get("task_queue_backlog_before")
        backlog_after = resource_payload.get("task_queue_backlog_after")
        active_before = resource_payload.get("active_slots_before")
        active_after = resource_payload.get("active_slots_after")
        bounded_counts = (
            type(backlog_before) is int
            and type(backlog_after) is int
            and type(active_before) is int
            and type(active_after) is int
            and 0 <= backlog_after <= backlog_before
            and 0 <= active_after <= active_before
        )
        result["resource_leak_free_verified"] = (
            closed_workflow_ids == workflow_ids
            and open_workflow_ids == set()
            and bounded_counts
            and _utc_timestamp(resource_payload.get("observed_at")) is not None
        )
    return result


def _load_pending_control_evidence(path: Path) -> tuple[str, object]:
    try:
        raw_json = path.read_bytes().decode("utf-8", errors="strict")
        document = _strict_json_loads(raw_json)
        schema = _strict_json_loads(CONTROL_EVIDENCE_SCHEMA_PATH.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _NonFiniteJsonError) as exc:
        raise ValueError("CAPACITY_APPROVAL_CONTROL_EVIDENCE_INVALID") from exc
    if not isinstance(document, dict) or not isinstance(schema, dict):
        raise ValueError("CAPACITY_APPROVAL_CONTROL_EVIDENCE_INVALID")
    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)
    )
    if errors:
        raise ValueError("CAPACITY_APPROVAL_CONTROL_EVIDENCE_SCHEMA_INVALID")
    return raw_json, document


async def _get_json(
    client: httpx.AsyncClient,
    path: str,
) -> tuple[Sample, object | None]:
    started = time.monotonic()
    response = await client.get(_request_path(client, path))
    sample = Sample(
        status=response.status_code,
        latency_seconds=max(time.monotonic() - started, 0.0),
        error_code=_error_code(response),
    )
    if response.status_code != 200:
        return sample, None
    try:
        return sample, _strict_json_loads(response.content)
    except (UnicodeDecodeError, json.JSONDecodeError, _NonFiniteJsonError):
        return sample, None


def _action_matches_manifest(action: object, expected: dict[str, str]) -> bool:
    if not isinstance(action, dict):
        return False
    return (
        action.get("action_id") == expected["action_id"]
        and action.get("run_id") == expected["run_id"]
        and action.get("payload_hash") == expected["payload_hash"]
        and action.get("approvals_received") == 0
        and action.get("status") == "pending_approval"
        and _utc_timestamp(action.get("expires_at")) == _utc_timestamp(expected["expires_at"])
    )


async def approvals(
    client: httpx.AsyncClient,
    *,
    manifest_path: Path,
    control_evidence_path: Path | None = None,
    control_evidence_uri: str = "",
    release_id: str = "",
    git_sha: str = "",
    image_digest: str = "",
) -> ScenarioResult:
    rows = _approval_manifest(manifest_path)
    rows_by_run: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        rows_by_run.setdefault(row["run_id"], []).append(row)

    semaphore = asyncio.Semaphore(min(len(rows_by_run), 100))

    async def query_run(
        run_id: str,
    ) -> tuple[str, Sample, object | None, Sample, object | None]:
        async with semaphore:
            action_sample, actions_document = await _get_json(
                client,
                f"/v1/runs/{run_id}/actions",
            )
            run_sample, run_document = await _get_json(client, f"/v1/runs/{run_id}")
            return run_id, action_sample, actions_document, run_sample, run_document

    query_results = await asyncio.gather(*(query_run(run_id) for run_id in rows_by_run))
    samples: list[Sample] = []
    matched_action_ids: set[str] = set()
    state_query_verified = True
    for run_id, action_sample, actions_document, run_sample, run_document in query_results:
        samples.extend((action_sample, run_sample))
        expected_rows = rows_by_run[run_id]
        if not isinstance(actions_document, list) or not isinstance(run_document, dict):
            state_query_verified = False
            continue
        action_rows = [action for action in actions_document if isinstance(action, dict)]
        action_ids = [action.get("action_id") for action in action_rows]
        if len(action_rows) != len(actions_document) or len(action_ids) != len(set(action_ids)):
            state_query_verified = False
            continue
        actions_by_id = {str(action["action_id"]): action for action in action_rows}
        pending_actions = run_document.get("pending_actions")
        pending_rows = pending_actions if isinstance(pending_actions, list) else []
        pending_action_ids = {
            str(pending["action_id"])
            for pending in pending_rows
            if isinstance(pending, dict) and isinstance(pending.get("action_id"), str)
        }
        run_valid = (
            run_document.get("run_id") == run_id
            and run_document.get("status") == "waiting_approval"
            and len(pending_rows)
            == len([pending for pending in pending_rows if isinstance(pending, dict)])
        )
        if not run_valid:
            state_query_verified = False
        for expected in expected_rows:
            action = actions_by_id.get(expected["action_id"])
            matched = _action_matches_manifest(action, expected)
            pending_on_run = expected["action_id"] in pending_action_ids
            if matched and pending_on_run and run_valid:
                matched_action_ids.add(expected["action_id"])
            else:
                state_query_verified = False

    pending_approval_count = len(matched_action_ids)
    state_query_verified = state_query_verified and pending_approval_count == len(rows)
    manifest_bytes = await asyncio.to_thread(manifest_path.read_bytes)
    manifest_sha256 = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    control_evidence: object | None = None
    control_evidence_raw_json: str | None = None
    control_evidence_sha256: str | None = None
    control_evidence_error: str | None
    if control_evidence_path is None or not control_evidence_uri:
        operational_controls = {
            "notification_delivery_verified": False,
            "expiry_processing_verified": False,
            "resource_leak_free_verified": False,
        }
        control_evidence_error = "CAPACITY_APPROVAL_CONTROL_EVIDENCE_REQUIRED"
    else:
        control_evidence_raw_json, control_evidence = _load_pending_control_evidence(
            control_evidence_path
        )
        control_evidence_sha256 = _raw_json_sha256(control_evidence_raw_json)
        uri_verified = _is_content_addressed_uri(
            control_evidence_uri,
            control_evidence_sha256,
        )
        operational_controls = (
            _derive_pending_control_checks(
                control_evidence,
                release_id=release_id,
                git_sha=git_sha,
                image_digest=image_digest,
                manifest_sha256=manifest_sha256,
                action_ids={row["action_id"] for row in rows},
                run_ids=set(rows_by_run),
                workflow_ids={row["workflow_id"] for row in rows},
            )
            if uri_verified
            else {
                "notification_delivery_verified": False,
                "expiry_processing_verified": False,
                "resource_leak_free_verified": False,
            }
        )
        control_evidence_error = (
            None
            if all(operational_controls.values())
            else "CAPACITY_APPROVAL_CONTROL_EVIDENCE_UNVERIFIED"
        )
    passed = (
        state_query_verified
        and pending_approval_count >= 1000
        and all(operational_controls.values())
    )
    return _summarize(
        "pending_approval_backlog_at_least_one_thousand",
        samples,
        passed=passed,
        evidence={
            "pending_approval_count": pending_approval_count,
            "unique_action_count": len(matched_action_ids),
            "queried_run_count": len(rows_by_run),
            "pending_action_ids": sorted(matched_action_ids),
            "queried_run_ids": sorted(rows_by_run),
            "workflow_ids": sorted({row["workflow_id"] for row in rows}),
            "manifest_sha256": manifest_sha256,
            "observed_status": (
                "pending_approval" if pending_approval_count == len(rows) else "unverified"
            ),
            "status_query_verified": state_query_verified,
            "operational_control_evidence_raw_json": control_evidence_raw_json,
            "operational_control_evidence_sha256": control_evidence_sha256,
            "operational_control_evidence_uri": control_evidence_uri or None,
            "operational_control_evidence_error": control_evidence_error,
            **operational_controls,
        },
    )


def _args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", choices=("staging",), required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--base-url", default=os.getenv("CAPACITY_BASE_URL", ""))
    parser.add_argument("--token-env", default="CAPACITY_BEARER_TOKEN")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--baseline-rps", type=float, default=1.0)
    parser.add_argument("--burst-duration-seconds", type=int, default=60)
    parser.add_argument("--tool-baseline-path", default="")
    parser.add_argument("--tool-degraded-path", default="")
    parser.add_argument("--tool-samples", type=int, default=50)
    parser.add_argument("--persistent-429-path", default="")
    parser.add_argument("--persistent-429-samples", type=int, default=200)
    parser.add_argument("--approval-manifest", type=Path)
    parser.add_argument("--approval-control-evidence", type=Path)
    parser.add_argument("--approval-control-evidence-uri", default="")
    parser.add_argument(
        "--scenarios",
        default="burst,long_runs,tool_latency,persistent_429,artifacts,approvals",
    )
    return parser.parse_args()


async def _main(args: argparse.Namespace) -> int:
    release_id, git_sha, image_digest = _validated_release_identity(
        args.release_id,
        args.git_sha,
        args.image_digest,
    )
    base_url = args.base_url.strip().rstrip("/")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("CAPACITY_STAGING_HTTPS_BASE_URL_REQUIRED")
    token = os.getenv(args.token_env, "").strip()
    if not token:
        raise ValueError(f"CAPACITY_TOKEN_REQUIRED:{args.token_env}")
    selected = {item.strip() for item in args.scenarios.split(",") if item.strip()}
    _require_complete_scenario_set(selected)
    if not math.isfinite(args.baseline_rps) or args.baseline_rps <= 0:
        raise ValueError("CAPACITY_BASELINE_RPS_INVALID")
    if args.burst_duration_seconds < 60:
        raise ValueError("CAPACITY_BURST_DURATION_TOO_SHORT")
    if args.tool_samples < 50:
        raise ValueError("CAPACITY_TOOL_SAMPLE_COUNT_TOO_SMALL")
    if args.persistent_429_samples < 200:
        raise ValueError("CAPACITY_429_SAMPLE_COUNT_TOO_SMALL")
    timeout = httpx.Timeout(connect=10, read=3700, write=3700, pool=10)
    headers = {"Authorization": f"Bearer {token}"}
    results: list[ScenarioResult] = []
    async with httpx.AsyncClient(
        base_url=urljoin(base_url + "/", "./"),
        headers=headers,
        timeout=timeout,
        trust_env=False,
    ) as client:
        if "burst" in selected:
            results.append(
                await burst_runs(
                    client,
                    baseline_rps=args.baseline_rps,
                    duration_seconds=args.burst_duration_seconds,
                )
            )
        if "long_runs" in selected:
            results.append(await long_runs(client))
        if "tool_latency" in selected:
            if not args.tool_baseline_path or not args.tool_degraded_path:
                raise ValueError("CAPACITY_TOOL_LATENCY_PATHS_REQUIRED")
            results.append(
                await tool_latency(
                    client,
                    baseline_path=args.tool_baseline_path,
                    degraded_path=args.tool_degraded_path,
                    sample_count=args.tool_samples,
                )
            )
        if "persistent_429" in selected:
            if not args.persistent_429_path:
                raise ValueError("CAPACITY_PERSISTENT_429_PATH_REQUIRED")
            results.append(
                await persistent_429(
                    client,
                    path=args.persistent_429_path,
                    sample_count=args.persistent_429_samples,
                )
            )
        if "artifacts" in selected:
            results.append(await streaming_artifacts(client))
        if "approvals" in selected:
            if args.approval_manifest is None:
                raise ValueError("CAPACITY_APPROVAL_MANIFEST_REQUIRED")
            if args.approval_control_evidence is None or not args.approval_control_evidence_uri:
                raise ValueError("CAPACITY_APPROVAL_CONTROL_EVIDENCE_REQUIRED")
            results.append(
                await approvals(
                    client,
                    manifest_path=args.approval_manifest,
                    control_evidence_path=args.approval_control_evidence,
                    control_evidence_uri=args.approval_control_evidence_uri,
                    release_id=release_id,
                    git_sha=git_sha,
                    image_digest=image_digest,
                )
            )

    document = {
        "schema_version": "1.0",
        "release_id": release_id,
        "git_sha": git_sha,
        "image_digest": image_digest,
        "environment": args.environment,
        "base_url_origin": f"{parsed.scheme}://{parsed.netloc}",
        "generated_at_unix": int(time.time()),
        "passed": bool(results) and all(result.passed for result in results),
        "scenarios": [asdict(result) for result in results],
        "latency_summary": {
            "median_p95_seconds": statistics.median(result.p95_seconds for result in results)
            if results
            else 0,
        },
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if document["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main(_args())))
