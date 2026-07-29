from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from deploy.ci.validate_operational_readiness import validate_gate_reports, validate_readiness
from tests.e2e.release_assets.test_operational_readiness_validator import (
    GATE_REPORT_SCHEMA,
    GIT_SHA,
    IMAGE_DIGEST,
    RELEASE_ID,
    SCHEMA,
    _prepare_gate_reports,
    _run,
    readiness_evidence,
)


def test_operational_readiness_rejects_non_finite_raw_samples(tmp_path) -> None:
    def inject_negative_infinity(gate_id: str, raw_evidence: dict[str, object]) -> None:
        if gate_id == "cost_budget":
            measurements = raw_evidence["measurements"]
            assert isinstance(measurements, dict)
            measurement = measurements["cost_regression_lte_15_percent"]
            assert isinstance(measurement, dict)
            measurement["samples"] = [-float("inf")]

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_evidence_mutator=inject_negative_infinity,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_JSON_NON_FINITE" in blocked.stderr


def test_operational_readiness_rejects_digest_as_mutable_path_substring(tmp_path) -> None:
    def make_raw_uri_mutable(gate_id: str, report: dict[str, object]) -> None:
        if gate_id == "staging_e2e":
            raw = report["raw_evidence"]
            assert isinstance(raw, dict)
            digest = str(raw["sha256"])
            raw["uri"] = f"https://evidence.example.test/raw/staging_e2e/{digest}-mutable/latest"

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        report_mutator=make_raw_uri_mutable,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_GATE_RAW_EVIDENCE_URI_NOT_CONTENT_ADDRESSED" in blocked.stderr


class _ExplodingStream(httpx.SyncByteStream):
    def __init__(self) -> None:
        self.iterated = False

    def __iter__(self):
        self.iterated = True
        raise AssertionError("response body must not be read after an oversized Content-Length")
        yield b""  # pragma: no cover


class _CountingStream(httpx.SyncByteStream):
    def __init__(self) -> None:
        self.iterations = 0

    def __iter__(self):
        for _ in range(100):
            self.iterations += 1
            yield b"x" * 8


def test_operational_fetch_rejects_content_length_before_reading_body(tmp_path) -> None:
    evidence = readiness_evidence()
    _prepare_gate_reports(tmp_path, evidence)
    stream = _ExplodingStream()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "application/json",
                "Content-Length": "17",
            },
            stream=stream,
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="OPERATIONAL_GATE_REPORT_TOO_LARGE"):
            validate_gate_reports(
                evidence,
                json.loads(GATE_REPORT_SCHEMA.read_text(encoding="utf-8")),
                expected_release_id=RELEASE_ID,
                expected_git_sha=GIT_SHA,
                expected_image_digest=IMAGE_DIGEST,
                fetch_reports=True,
                bearer_token="token",
                http_client=client,
                maximum_report_bytes=16,
            )

    assert stream.iterated is False


def test_operational_fetch_stops_stream_when_decoded_body_exceeds_limit(tmp_path) -> None:
    evidence = readiness_evidence()
    _prepare_gate_reports(tmp_path, evidence)
    streams: list[_CountingStream] = []

    def handler(request: httpx.Request) -> httpx.Response:
        stream = _CountingStream()
        streams.append(stream)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match="OPERATIONAL_GATE_REPORT_TOO_LARGE"):
            validate_gate_reports(
                evidence,
                json.loads(GATE_REPORT_SCHEMA.read_text(encoding="utf-8")),
                expected_release_id=RELEASE_ID,
                expected_git_sha=GIT_SHA,
                expected_image_digest=IMAGE_DIGEST,
                fetch_reports=True,
                bearer_token="token",
                http_client=client,
                maximum_report_bytes=16,
            )

    assert streams
    assert all(stream.iterations <= 3 for stream in streams)


def test_gate_report_uri_requires_exact_terminal_digest_segment() -> None:
    evidence = readiness_evidence()
    gate = evidence["gates"]["staging_e2e"]
    digest = gate["report_sha256"]
    gate["evidence_uri"] = f"https://evidence.example.test/gates/{digest}-mutable/latest"

    with pytest.raises(
        ValueError,
        match="OPERATIONAL_READINESS_GATE_URI_NOT_CONTENT_ADDRESSED",
    ):
        validate_readiness(
            evidence,
            json.loads(SCHEMA.read_text(encoding="utf-8")),
            expected_release_id=RELEASE_ID,
            expected_git_sha=GIT_SHA,
            expected_image_digest=IMAGE_DIGEST,
            expected_signer_identity=(
                "https://github.com/example/release-governance/"
                ".github/workflows/publish.yml@refs/heads/main"
            ),
            expected_signer_issuer="https://token.actions.githubusercontent.com",
            maximum_age_seconds=3600,
            minimum_retention_days=365,
        )


def _capacity_evidence(raw_report: dict[str, object]) -> dict[str, object]:
    scenarios = raw_report["scenarios"]
    assert isinstance(scenarios, list)
    scenario = next(
        row
        for row in scenarios
        if isinstance(row, dict)
        and row.get("name") == "pending_approval_backlog_at_least_one_thousand"
    )
    evidence = scenario["evidence"]
    assert isinstance(evidence, dict)
    return evidence


def test_capacity_control_checks_are_recomputed_not_self_reported(tmp_path) -> None:
    def replace_control_with_empty_document(raw_report: dict[str, object]) -> None:
        evidence = _capacity_evidence(raw_report)
        raw_json = "{}"
        digest = "sha256:" + hashlib.sha256(raw_json.encode()).hexdigest()
        evidence["operational_control_evidence_raw_json"] = raw_json
        evidence["operational_control_evidence_sha256"] = digest
        evidence["operational_control_evidence_uri"] = (
            f"https://evidence.example.test/capacity/control/{digest}"
        )

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_capacity_mutator=replace_control_with_empty_document,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_DERIVED_MISMATCH" in blocked.stderr
    assert "OPERATIONAL_CAPACITY_PENDING_APPROVAL_NOTIFICATIONS_UNVERIFIED" in blocked.stderr


@pytest.mark.parametrize("mutation", ("whitespace", "unicode-escape"))
def test_capacity_control_digest_binds_exact_raw_json_bytes(
    tmp_path,
    mutation: str,
) -> None:
    def mutate_bytes_without_digest(raw_report: dict[str, object]) -> None:
        evidence = _capacity_evidence(raw_report)
        raw_json = evidence["operational_control_evidence_raw_json"]
        assert isinstance(raw_json, str)
        if mutation == "whitespace":
            evidence["operational_control_evidence_raw_json"] = raw_json + "\n"
            return
        document = json.loads(raw_json)
        document["encoding_probe"] = "é"
        unescaped = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        digest = "sha256:" + hashlib.sha256(unescaped.encode()).hexdigest()
        evidence["operational_control_evidence_raw_json"] = unescaped.replace("é", "\\u00e9")
        evidence["operational_control_evidence_sha256"] = digest
        evidence["operational_control_evidence_uri"] = (
            f"https://evidence.example.test/capacity/control/{digest}"
        )

    blocked = _run(
        tmp_path,
        readiness_evidence(),
        raw_capacity_mutator=mutate_bytes_without_digest,
    )

    assert blocked.returncode == 2
    assert "OPERATIONAL_CAPACITY_CONTROL_EVIDENCE_RAW_BYTES_UNBOUND" in blocked.stderr
