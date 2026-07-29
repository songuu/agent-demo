"""Application-owned verifier gates that model output cannot override."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from agent_platform.domain.enums import TrustLevel
from agent_platform.domain.models import (
    CriterionVerification,
    TaskContract,
    WorkerOutput,
)


def aggregate_final_criterion_verifications(
    contract: TaskContract,
    outputs: dict[str, WorkerOutput],
    final_output: WorkerOutput,
) -> list[CriterionVerification]:
    """Select one contract-matching, final-output-observable check per criterion."""

    final_evidence_ids = {item.evidence_id for item in final_output.evidence}
    aggregated: list[CriterionVerification] = []
    for criterion in contract.success_criteria:
        final_matches = [
            check
            for check in final_output.criterion_verifications
            if check.criterion_id == criterion.id and check.method == criterion.verification
        ]
        candidates = final_matches or [
            check
            for output in outputs.values()
            for check in output.criterion_verifications
            if check.criterion_id == criterion.id
            and check.method == criterion.verification
            and set(check.evidence_ids) <= final_evidence_ids
        ]
        if candidates:
            aggregated.append(max(candidates, key=lambda check: check.checked_at))
    return aggregated


def deterministic_verification_findings(
    contract: TaskContract,
    outputs: dict[str, WorkerOutput],
) -> dict[str, Any]:
    """Evaluate every must criterion before any semantic model judgment."""

    evidence_by_id = {
        item.evidence_id: item for output in outputs.values() for item in output.evidence
    }
    evidence_ids = set(evidence_by_id)
    unsupported_claim_ids = [
        claim.claim_id
        for output in outputs.values()
        for claim in output.claims
        if not set(claim.evidence_ids) <= evidence_ids
    ]
    checks_by_criterion = defaultdict(list)
    for output in outputs.values():
        for check in output.criterion_verifications:
            checks_by_criterion[check.criterion_id].append(check)

    contract_criteria = {criterion.id: criterion for criterion in contract.success_criteria}
    hard_failures = [
        f"unknown success criterion verification: {criterion_id}"
        for criterion_id in sorted(set(checks_by_criterion) - set(contract_criteria))
    ]
    failed_criteria: list[str] = []
    requires_escalation = False

    for criterion in contract.success_criteria:
        if criterion.severity != "must":
            continue
        checks = checks_by_criterion.get(criterion.id, [])
        matching = [check for check in checks if check.method == criterion.verification]
        failure: str | None = None
        if not matching:
            failure = (
                f"must criterion {criterion.id!r} has no {criterion.verification} verification"
            )
        elif any(not check.passed for check in matching):
            reasons = sorted(
                {
                    check.failure_reason or "verification failed without a reason"
                    for check in matching
                    if not check.passed
                }
            )
            failure = (
                f"must criterion {criterion.id!r} failed "
                f"{criterion.verification} verification: {'; '.join(reasons)}"
            )
        elif (
            criterion.evidence_required
            or criterion.verification in {"evidence", "environment", "human"}
        ) and any(not check.evidence_ids for check in matching):
            failure = (
                f"must criterion {criterion.id!r} has no evidence for "
                f"{criterion.verification} verification"
            )
        elif any(not set(check.evidence_ids) <= evidence_ids for check in matching):
            failure = f"must criterion {criterion.id!r} references inaccessible evidence"
        elif criterion.verification in {"environment", "human"} and any(
            check.verifier_version is None for check in matching
        ):
            failure = (
                f"must criterion {criterion.id!r} has no versioned "
                f"{criterion.verification} verifier"
            )
        elif criterion.verification in {"environment", "human"} and any(
            evidence_by_id[evidence_id].trust is not TrustLevel.TRUSTED
            for check in matching
            for evidence_id in check.evidence_ids
        ):
            failure = (
                f"must criterion {criterion.id!r} uses untrusted evidence for "
                f"{criterion.verification} verification"
            )

        if failure is not None:
            failed_criteria.append(criterion.id)
            hard_failures.append(failure)
            requires_escalation = requires_escalation or criterion.verification == "human"

    return {
        "hard_failures": hard_failures,
        "unsupported_claim_ids": unsupported_claim_ids,
        "failed_criteria": failed_criteria,
        "requires_escalation": requires_escalation,
    }
