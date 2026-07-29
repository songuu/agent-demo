from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parents[3] / "src"))

from agent_platform.domain import (
    ActionProposal,
    ArtifactRef,
    Claim,
    CommitReceipt,
    CriterionVerification,
    DataClassification,
    DataScope,
    Evidence,
    FinalResponse,
    MemoryCandidate,
    Principal,
    RiskLevel,
    SuccessCriterion,
    TaskContract,
    TrustLevel,
    VerificationResult,
    WorkerOutput,
)


def principal() -> Principal:
    return Principal(
        user_id="user-1",
        tenant_id="tenant-1",
        roles={"analyst"},
        scopes={"knowledge:read"},
        auth_strength="mfa",
        session_id="session-1",
    )


def contract(**overrides: object) -> TaskContract:
    values: dict[str, object] = {
        "goal": "Produce a source-backed market report",
        "success_criteria": [
            SuccessCriterion(
                id="sc-1",
                description="Every key conclusion has evidence",
                severity="must",
                verification="evidence",
                evidence_required=True,
            )
        ],
        "principal": principal(),
        "data_scope": DataScope(
            tenant_id="tenant-1",
            resource_types={"knowledge"},
            classifications={DataClassification.INTERNAL},
        ),
        "risk": RiskLevel.MEDIUM,
        "allowed_capabilities": {"knowledge.search", "artifact.create"},
        "max_cost_usd": Decimal("5.00"),
        "max_duration_seconds": 600,
        "max_parallelism": 2,
        "max_replans": 1,
        "external_write_policy": "prepare_only",
    }
    values.update(overrides)
    return TaskContract(**values)


class StrictModelTests(unittest.TestCase):
    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            Principal(
                user_id="user-1",
                tenant_id="tenant-1",
                auth_strength="mfa",
                unexpected="not-allowed",
            )

        self.assertIn("extra_forbidden", str(caught.exception))

    def test_contract_rejects_cross_tenant_scope(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            contract(
                data_scope=DataScope(
                    tenant_id="tenant-2",
                    resource_types={"knowledge"},
                )
            )

        self.assertIn("TASK_CONTRACT_TENANT_MISMATCH", str(caught.exception))
        self.assertIn("tenant-1", str(caught.exception))
        self.assertIn("tenant-2", str(caught.exception))

    def test_contract_and_principal_are_immutable(self) -> None:
        value = contract()
        with self.assertRaises(ValidationError):
            value.goal = "changed"  # type: ignore[misc]
        with self.assertRaises(ValidationError):
            value.principal.tenant_id = "tenant-2"  # type: ignore[misc]

    def test_action_proposal_cannot_contain_trusted_control_fields(self) -> None:
        for reserved in (
            "tenant_id",
            "principal_id",
            "payload_hash",
            "idempotency_key",
            "approval_policy",
            "status",
            "credential_scope",
        ):
            with self.subTest(reserved=reserved), self.assertRaises(ValidationError):
                ActionProposal(
                    action_type="email.send",
                    parameters={"recipients": ["a@example.test"], reserved: "forged"},
                    rationale="Send approved summary",
                    expected_effect="One email is prepared",
                )

    def test_datetime_fields_require_timezone_and_normalize_to_utc(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            Evidence(
                source_type="document",
                source_id="doc-1",
                captured_at=datetime(2026, 7, 23, 12, 0),
                content_hash="a" * 64,
                supports_claim_ids=["claim-1"],
                trust=TrustLevel.TRUSTED,
            )
        self.assertIn("TIMEZONE_REQUIRED", str(caught.exception))

        evidence = Evidence(
            source_type="document",
            source_id="doc-1",
            captured_at=datetime(2026, 7, 23, 20, 0, tzinfo=UTC),
            content_hash="a" * 64,
            supports_claim_ids=["claim-1"],
            trust=TrustLevel.TRUSTED,
        )
        self.assertEqual(evidence.captured_at.tzinfo, UTC)


class EvidenceInvariantTests(unittest.TestCase):
    def _evidence(self, claim_id: str = "claim-1") -> Evidence:
        return Evidence(
            source_type="document",
            source_id="doc-1",
            locator="page:3",
            captured_at=datetime.now(UTC),
            content_hash="a" * 64,
            supports_claim_ids=[claim_id],
            trust=TrustLevel.TRUSTED,
        )

    def test_criterion_verification_round_trips_and_legacy_output_defaults_empty(self) -> None:
        evidence = Evidence(
            source_type="environment_health",
            source_id="deployment-1",
            locator="https://agent.example.test/health/ready",
            captured_at=datetime.now(UTC),
            content_hash="b" * 64,
            supports_criterion_ids=["sc-environment"],
            trust=TrustLevel.TRUSTED,
        )
        output = WorkerOutput(
            summary="Deployment health was verified.",
            evidence=[evidence],
            criterion_verifications=[
                CriterionVerification(
                    criterion_id="sc-environment",
                    method="environment",
                    passed=True,
                    checked_at=datetime.now(UTC),
                    evidence_ids=[evidence.evidence_id],
                    details={"status_code": 200},
                    verifier_version="health-check@1",
                )
            ],
        )

        restored = WorkerOutput.model_validate_json(output.model_dump_json())
        legacy = WorkerOutput.model_validate_json('{"summary":"legacy output"}')

        final_response = FinalResponse(
            summary="Deployment health was verified.",
            evidence=[evidence],
            criterion_verifications=output.criterion_verifications,
        )
        restored_final = FinalResponse.model_validate_json(final_response.model_dump_json())
        legacy_final = FinalResponse.model_validate_json('{"summary":"legacy final response"}')

        self.assertEqual(restored, output)
        self.assertEqual(legacy.criterion_verifications, [])
        self.assertEqual(restored_final, final_response)
        self.assertEqual(legacy_final.criterion_verifications, [])

    def test_worker_output_requires_reciprocal_claim_evidence_links(self) -> None:
        evidence = self._evidence()
        output = WorkerOutput(
            summary="Verified result",
            claims=[
                Claim(
                    claim_id="claim-1",
                    statement="The source supports the conclusion.",
                    confidence=0.9,
                    evidence_ids=[evidence.evidence_id],
                )
            ],
            evidence=[evidence],
        )
        self.assertEqual(output.claims[0].claim_id, "claim-1")

        with self.assertRaises(ValidationError) as caught:
            WorkerOutput(
                summary="Unsupported result",
                claims=[
                    Claim(
                        claim_id="claim-1",
                        statement="Unsupported",
                        confidence=0.9,
                        evidence_ids=[uuid4()],
                    )
                ],
                evidence=[evidence],
            )
        self.assertIn("WORKER_OUTPUT_UNKNOWN_EVIDENCE", str(caught.exception))

    def test_duplicate_claim_and_evidence_ids_are_rejected(self) -> None:
        evidence = self._evidence()
        claim = Claim(
            claim_id="claim-1",
            statement="A fact",
            confidence=0.8,
            evidence_ids=[evidence.evidence_id],
        )
        with self.assertRaises(ValidationError) as caught:
            WorkerOutput(
                summary="Duplicates",
                claims=[claim, claim],
                evidence=[evidence],
            )
        self.assertIn("WORKER_OUTPUT_DUPLICATE_CLAIM", str(caught.exception))

    def test_final_response_only_accepts_verified_receipts(self) -> None:
        artifact = ArtifactRef(
            artifact_id=uuid4(),
            sha256="b" * 64,
            classification=DataClassification.INTERNAL,
        )
        receipt = CommitReceipt(
            external_operation_id="message-1",
            committed_at=datetime.now(UTC),
            result_summary={"status": "sent"},
            idempotency_key="idem-1",
            verification=VerificationResult(
                passed=True,
                verified_at=datetime.now(UTC),
                method="read_after_write",
                details={"message_id": "message-1"},
            ),
        )
        response = FinalResponse(
            summary="Completed",
            claims=[],
            evidence=[],
            artifacts=[artifact],
            receipts=[receipt],
        )
        self.assertEqual(response.receipts[0].idempotency_key, "idem-1")

        with self.assertRaises(ValidationError) as caught:
            FinalResponse(
                summary="Not actually complete",
                receipts=[
                    receipt.model_copy(
                        update={
                            "verification": VerificationResult(
                                passed=False,
                                verified_at=datetime.now(UTC),
                                method="read_after_write",
                                details={"reason": "not visible"},
                            )
                        }
                    )
                ],
            )
        self.assertIn("FINAL_RESPONSE_UNVERIFIED_RECEIPT", str(caught.exception))

    def test_memory_candidate_requires_expiry_for_sensitive_data(self) -> None:
        with self.assertRaises(ValidationError) as caught:
            MemoryCandidate(
                subject_type="project",
                subject_id="project-1",
                memory_type="decision",
                content={"decision": "restricted detail"},
                source_refs=[],
                classification=DataClassification.RESTRICTED,
                confidence=Decimal("0.9000"),
                purpose="Preserve an approved decision",
                owner_id="user-1",
                write_policy="explicit_approval",
                user_visible=True,
            )
        self.assertIn("MEMORY_RETENTION_REQUIRED", str(caught.exception))

        value = MemoryCandidate(
            subject_type="project",
            subject_id="project-1",
            memory_type="decision",
            content={"decision": "restricted detail"},
            source_refs=[],
            classification=DataClassification.RESTRICTED,
            confidence=Decimal("0.9000"),
            purpose="Preserve an approved decision",
            owner_id="user-1",
            write_policy="explicit_approval",
            user_visible=True,
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        self.assertTrue(value.user_visible)


if __name__ == "__main__":
    unittest.main()
