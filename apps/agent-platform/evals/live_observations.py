"""Independent derivation of grader and reviewer observations from staging data."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

JsonObject = dict[str, Any]
_SHA256 = re.compile(r"^(?:sha256:)?[a-f0-9]{64}$")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _rows(value: object) -> list[JsonObject]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _result_schema_valid(final: JsonObject) -> bool:
    if final.get("schema_version") != "1.0":
        return False
    if not isinstance(final.get("summary"), str) or not final["summary"]:
        return False
    for field in (
        "claims",
        "evidence",
        "criterion_verifications",
        "artifacts",
        "receipts",
        "caveats",
        "incomplete_items",
    ):
        if not isinstance(final.get(field), list):
            return False

    claims = _rows(final["claims"])
    evidence = _rows(final["evidence"])
    if len(claims) != len(final["claims"]) or len(evidence) != len(final["evidence"]):
        return False
    evidence_by_id: dict[str, JsonObject] = {}
    for row in evidence:
        evidence_id = row.get("evidence_id")
        if (
            not isinstance(evidence_id, str)
            or not evidence_id
            or evidence_id in evidence_by_id
            or not isinstance(row.get("source_type"), str)
            or not row["source_type"]
            or not isinstance(row.get("source_id"), str)
            or not row["source_id"]
            or _SHA256.fullmatch(str(row.get("content_hash", ""))) is None
        ):
            return False
        evidence_by_id[evidence_id] = row
    claim_ids: set[str] = set()
    for claim in claims:
        claim_id = claim.get("claim_id")
        links = claim.get("evidence_ids")
        if (
            not isinstance(claim_id, str)
            or not claim_id
            or claim_id in claim_ids
            or not isinstance(links, list)
            or not links
            or any(str(link) not in evidence_by_id for link in links)
        ):
            return False
        claim_ids.add(claim_id)
        for link in links:
            supported = evidence_by_id[str(link)].get("supports_claim_ids")
            if not isinstance(supported, list) or claim_id not in supported:
                return False
    return True


def _audit_integrity(
    audit: JsonObject,
    *,
    run_id: str,
) -> JsonObject:
    events = _rows(audit.get("events"))
    sequences = [row.get("sequence_no") for row in events]
    integer_sequences = [
        value for value in sequences if isinstance(value, int) and not isinstance(value, bool)
    ]
    contiguous = bool(integer_sequences) and integer_sequences == list(
        range(integer_sequences[0], integer_sequences[0] + len(integer_sequences))
    )
    payload_hashes_valid = all(
        _SHA256.fullmatch(str(row.get("payload_hash", ""))) is not None for row in events
    )
    return {
        "sequence_contiguous": contiguous,
        "payload_hashes_valid": payload_hashes_valid,
        "run_binding_verified": audit.get("run_id") == run_id,
        "export_actor_observed": (
            isinstance(audit.get("exported_by"), str) and bool(audit["exported_by"])
        ),
    }


def _metric_observations(
    final: JsonObject,
    *,
    criterion_id: str,
) -> tuple[JsonObject, list[JsonObject]]:
    observations: JsonObject = {}
    claims: list[JsonObject] = []
    for row in _rows(final.get("criterion_verifications")):
        if row.get("criterion_id") != criterion_id:
            continue
        details = row.get("details")
        if not isinstance(details, dict):
            continue
        raw_observations = details.get("metric_observations")
        raw_claims = details.get("metric_claims")
        if isinstance(raw_observations, dict):
            observations = {
                str(name): value
                for name, value in raw_observations.items()
                if isinstance(value, (int, float)) and not isinstance(value, bool)
            }
        if isinstance(raw_claims, list):
            claims = [row for row in raw_claims if isinstance(row, dict)]
    return observations, claims


def derive_live_observations(
    snapshot: JsonObject,
    audit: JsonObject,
    *,
    run_id: str,
    criterion_id: str,
) -> JsonObject:
    result = snapshot.get("result")
    final = result if isinstance(result, dict) else {}
    metric_observations, metric_claims = _metric_observations(
        final,
        criterion_id=criterion_id,
    )
    evidence = _rows(final.get("evidence"))
    return {
        "result_schema_valid": _result_schema_valid(final),
        "final_result": final,
        "evidence_observations": evidence,
        "metric_observations": metric_observations,
        "metric_claims": metric_claims,
        "audit_integrity": _audit_integrity(audit, run_id=run_id),
        "snapshot_sha256": canonical_sha256(snapshot),
        "audit_sha256": canonical_sha256(audit),
    }


def build_review_subject(
    *,
    release_id: str,
    case: JsonObject,
    case_report: JsonObject,
) -> JsonObject:
    """Create the exact immutable object sent to independent reviewers."""

    final_result = case_report.get("final_result")
    final = final_result if isinstance(final_result, dict) else {}
    return {
        "schema_version": "1.1",
        "release_id": release_id,
        "case_id": case_report["case_id"],
        "source_case_id": case_report["source_case_id"],
        "run_id": case_report["run_id"],
        "dataset": case_report["dataset"],
        "category": case_report["category"],
        "use_case": case_report["use_case"],
        "risk": case_report["risk"],
        "source_scenario_sha256": case_report["source_scenario_sha256"],
        "input_sha256": case_report["input_sha256"],
        "final_result": final,
        "claims": _rows(final.get("claims")),
        "evidence": _rows(final.get("evidence")),
        "audit_ref": case_report.get("observation_sources", {}).get("audit"),
        "artifact_refs": case_report.get("artifact_observations", []),
        "grader_results": case_report.get("grader_results", []),
        "expected_capability_trajectory": case_report.get(
            "expected_capability_trajectory",
            [],
        ),
        "observed_capability_trajectory": case_report.get(
            "observed_capability_trajectory",
            [],
        ),
        "tool_trajectory_binding": case_report.get("tool_trajectory_binding"),
        "fault_injection_receipt": case_report.get("fault_injection_receipt"),
        "case_contract_sha256": canonical_sha256(
            {
                "input": case["input"],
                "expected": case["expected"],
                "graders": case["graders"],
            }
        ),
    }
