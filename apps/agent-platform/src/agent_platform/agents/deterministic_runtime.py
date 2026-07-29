"""Deterministic reference runtime for CI, local use, and provider-outage drills.

It follows the same TaskContract, ToolGateway, Evidence, Artifact, and Action
contracts as the model runtime. It is not a production model replacement.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from agent_platform.agents.verification import deterministic_verification_findings
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.application.records import ArtifactRecord
from agent_platform.domain.enums import DataClassification, TrustLevel
from agent_platform.domain.models import (
    ActionProposal,
    Claim,
    CriterionVerification,
    Evidence,
    ExecutionPlan,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
    validate_plan_against_contract,
)
from agent_platform.infrastructure.artifacts.trusted_generated import (
    build_trusted_generated_json,
)
from agent_platform.tools.models import ToolContext


@dataclass(slots=True)
class RuntimeExecutionContext:
    run_id: UUID
    contract: TaskContract
    correlation_id: str
    gateway: Any
    artifact_store: Any
    budget: BudgetLedger | None = None


class DeterministicAgentRuntime:
    @staticmethod
    def audit_metadata(
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, Any]:
        del contract, task, retry_count
        if role not in {"planner", "worker"}:
            raise ValueError("AUDIT_RUNTIME_ROLE_UNSUPPORTED")
        return {
            "model_name": "deterministic-reference-runtime",
            "model_settings": {"provider": "none", "deterministic": True},
            "prompt_id": "not-applicable",
            "prompt_version": "not-applicable",
        }

    async def plan(self, context: RuntimeExecutionContext, contract: TaskContract) -> ExecutionPlan:
        del context
        markets = contract.constraints.get("markets", [])
        if not isinstance(markets, list) or not markets:
            markets = ["general"]
        research_capability = (
            ["knowledge.search"] if "knowledge.search" in contract.allowed_capabilities else []
        )
        tasks: list[TaskSpec] = []
        for market in markets[:10]:
            normalized = re.sub(r"[^a-z0-9]+", "_", str(market).casefold()).strip("_")
            tasks.append(
                TaskSpec(
                    id=f"research_{normalized or 'market'}",
                    kind="research",
                    objective=f"Research {market} using authorized sources",
                    capability_names=research_capability,
                    output_schema="WorkerOutput@1.0",
                    risk=contract.risk,
                    max_turns=4,
                    timeout_seconds=30,
                    max_tool_calls=1 if research_capability else 0,
                    estimated_cost_usd=Decimal("0.10"),
                )
            )
        synthesis_id = "synthesize_report"
        tasks.append(
            TaskSpec(
                id=synthesis_id,
                kind="synthesis",
                objective="Synthesize only evidence-backed claims into the requested report",
                depends_on=[task.id for task in tasks],
                capability_names=(
                    ["artifact.create"]
                    if "artifact.create" in contract.allowed_capabilities
                    else []
                ),
                output_schema="WorkerOutput@1.0",
                risk=contract.risk,
                max_turns=4,
                timeout_seconds=30,
                max_tool_calls=0,
                estimated_cost_usd=Decimal("0.10"),
            )
        )
        final_task_id = synthesis_id
        if "email.prepare" in contract.allowed_capabilities:
            tasks.append(
                TaskSpec(
                    id="prepare_email",
                    kind="synthesis",
                    objective="Prepare a management email from the verified report",
                    depends_on=[synthesis_id],
                    capability_names=["email.prepare"],
                    output_schema="WorkerOutput@1.0",
                    risk=contract.risk,
                    max_turns=2,
                    timeout_seconds=30,
                    max_tool_calls=1,
                    estimated_cost_usd=Decimal("0.10"),
                    approval_boundary="prepare_only",
                )
            )
            final_task_id = "prepare_email"
        plan = ExecutionPlan(
            plan_version=1,
            assumptions=["Only registered sources and sandbox actions are used."],
            tasks=tasks,
            final_task_id=final_task_id,
            expected_total_cost_usd=sum((task.estimated_cost_usd for task in tasks), Decimal("0")),
        )
        validate_plan_against_contract(
            plan,
            contract,
            known_capabilities=frozenset({"knowledge.search", "artifact.create", "email.prepare"}),
        )
        return plan

    async def execute_task(
        self,
        context: RuntimeExecutionContext,
        task: TaskSpec,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        if task.kind == "research":
            return await self._research(context, task)
        if task.id == "synthesize_report":
            return await self._synthesize(context, dependencies)
        if task.id == "prepare_email":
            return await self._prepare_email(context, dependencies)
        return WorkerOutput(
            summary=f"Task {task.id} completed without external capabilities",
            uncertainties=["No registered capability was needed."],
        )

    async def verify(
        self,
        context: RuntimeExecutionContext,
        contract: TaskContract,
        plan: ExecutionPlan,
        outputs: dict[str, WorkerOutput],
    ) -> VerificationReport:
        del context
        final = outputs.get(plan.final_task_id)
        synthesis = outputs.get("synthesize_report", final)
        if final is None or synthesis is None:
            return VerificationReport(
                verdict="revise",
                failed_criteria=[
                    item.id for item in contract.success_criteria if item.severity == "must"
                ],
                missing_evidence=["Final task output is missing."],
                repair_instructions=["Execute the final task before verification."],
            )
        deterministic = deterministic_verification_findings(contract, outputs)
        if deterministic["hard_failures"]:
            return VerificationReport(
                verdict=("escalate" if deterministic["requires_escalation"] else "revise"),
                failed_criteria=deterministic["failed_criteria"],
                unsupported_claim_ids=deterministic["unsupported_claim_ids"],
                missing_evidence=deterministic["hard_failures"],
                repair_instructions=[
                    "Repair deterministic criterion verification failures before completion."
                ],
            )
        return VerificationReport(verdict="pass")

    async def _research(self, context: RuntimeExecutionContext, task: TaskSpec) -> WorkerOutput:
        if "knowledge.search" not in task.capability_names:
            return WorkerOutput(
                summary=f"No authorized source capability for {task.objective}",
                uncertainties=["Research could not be performed without a read capability."],
            )
        market = task.id.removeprefix("research_").upper()
        result = await context.gateway.call_read(
            self._tool_context(context, task),
            "knowledge.search",
            {"query": market, "limit": 8},
        )
        items = result.data.get("items", []) if isinstance(result.data, dict) else []
        if not items:
            return WorkerOutput(
                summary=f"No source matched {market}",
                uncertainties=[f"No authorized evidence was found for {market}."],
            )
        claims: list[Claim] = []
        evidence: list[Evidence] = []
        for index, item in enumerate(items):
            claim_id = f"{task.id}_claim_{index + 1}"
            captured_at = datetime.fromisoformat(item["captured_at"])
            source = Evidence(
                source_type="knowledge",
                source_id=item["source_id"],
                locator=item["uri"],
                captured_at=captured_at,
                content_hash=item["content_hash"],
                supports_claim_ids=[claim_id],
                trust=TrustLevel.UNTRUSTED,
            )
            evidence.append(source)
            claims.append(
                Claim(
                    claim_id=claim_id,
                    statement=item["content"],
                    confidence=0.8,
                    evidence_ids=[source.evidence_id],
                )
            )
        return WorkerOutput(
            summary=f"Found {len(evidence)} source(s) for {market}",
            claims=claims,
            evidence=evidence,
        )

    async def _synthesize(
        self,
        context: RuntimeExecutionContext,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        claims = [claim for output in dependencies.values() for claim in output.claims]
        evidence = [item for output in dependencies.values() for item in output.evidence]
        evidence_criterion_ids = {
            criterion.id
            for criterion in context.contract.success_criteria
            if criterion.verification == "evidence"
        }
        if evidence_criterion_ids:
            evidence = [
                item.model_copy(
                    update={
                        "supports_criterion_ids": sorted(
                            set(item.supports_criterion_ids) | evidence_criterion_ids
                        )
                    }
                )
                for item in evidence
            ]
        summary = (
            "Evidence-backed comparison completed."
            if claims
            else "No evidence-backed comparison could be completed."
        )
        artifacts: list[UUID] = []
        if "artifact.create" in context.contract.allowed_capabilities:
            content, scan_provenance = build_trusted_generated_json(
                {
                    "schema_version": "1.0",
                    "summary": summary,
                    "claims": [claim.model_dump(mode="json") for claim in claims],
                    "evidence": [item.model_dump(mode="json") for item in evidence],
                },
                kind="report",
                source="deterministic_runtime",
            )
            artifact = ArtifactRecord(
                artifact_id=uuid4(),
                tenant_id=context.contract.principal.tenant_id,
                run_id=context.run_id,
                kind="report",
                media_type="application/json",
                content=content,
                sha256=hashlib.sha256(content).hexdigest(),
                classification=DataClassification.INTERNAL.value,
                created_by=context.contract.principal.user_id,
                scan_status="trusted_generated",
                scan_provenance=scan_provenance,
            )
            await context.artifact_store.put(artifact)
            artifacts.append(artifact.artifact_id)
        return WorkerOutput(
            summary=summary,
            claims=claims,
            evidence=evidence,
            criterion_verifications=self._criterion_verifications(
                context.contract,
                evidence,
            ),
            artifacts=artifacts,
            uncertainties=[
                "Reference knowledge is illustrative; production adapters supply "
                "authoritative data."
            ],
        )

    async def _prepare_email(
        self,
        context: RuntimeExecutionContext,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        report = dependencies["synthesize_report"]
        recipients = context.contract.constraints.get("recipients", ["leader@example.test"])
        args = {
            "recipients": recipients,
            "subject": "Source-backed market comparison",
            "body": report.summary,
            "artifact_ids": [str(item) for item in report.artifacts],
        }
        await context.gateway.prepare(
            self._tool_context(
                context,
                TaskSpec(
                    id="prepare_email",
                    kind="synthesis",
                    objective="Prepare management email",
                    capability_names=["email.prepare"],
                    output_schema="WorkerOutput@1.0",
                    risk=context.contract.risk,
                    max_turns=2,
                    timeout_seconds=30,
                    max_tool_calls=1,
                    estimated_cost_usd=Decimal("0.10"),
                    approval_boundary="prepare_only",
                ),
            ),
            "email.prepare",
            args,
        )
        return WorkerOutput(
            summary="Email preview prepared; no message was sent.",
            claims=report.claims,
            evidence=report.evidence,
            criterion_verifications=report.criterion_verifications,
            artifacts=report.artifacts,
            action_proposals=[
                ActionProposal(
                    action_type="email.send",
                    parameters=args,
                    rationale="Send only the verified summary and final report after approval.",
                    expected_effect=(
                        "One sandbox email is delivered after CommitService verification."
                    ),
                )
            ],
            uncertainties=report.uncertainties,
        )

    @staticmethod
    def _criterion_verifications(
        contract: TaskContract,
        evidence: list[Evidence],
    ) -> list[CriterionVerification]:
        evidence_ids = [item.evidence_id for item in evidence[:100]]
        results: list[CriterionVerification] = []
        for criterion in contract.success_criteria:
            if criterion.verification == "schema":
                results.append(
                    CriterionVerification(
                        criterion_id=criterion.id,
                        method="schema",
                        passed=True,
                        checked_at=datetime.now(UTC),
                        verifier_version="deterministic-runtime@1",
                    )
                )
            elif criterion.verification == "evidence" and evidence_ids:
                results.append(
                    CriterionVerification(
                        criterion_id=criterion.id,
                        method="evidence",
                        passed=True,
                        checked_at=datetime.now(UTC),
                        evidence_ids=evidence_ids,
                        verifier_version="deterministic-runtime@1",
                    )
                )
            else:
                results.append(
                    CriterionVerification(
                        criterion_id=criterion.id,
                        method=criterion.verification,
                        passed=False,
                        checked_at=datetime.now(UTC),
                        failure_reason=(
                            "No accessible evidence was produced."
                            if criterion.verification == "evidence"
                            else f"{criterion.verification} verification was not performed."
                        ),
                        verifier_version="deterministic-runtime@1",
                    )
                )
        return results

    @staticmethod
    def _tool_context(context: RuntimeExecutionContext, task: TaskSpec) -> ToolContext:
        return ToolContext(
            run_id=context.run_id,
            task_id=task.id,
            plan_version=1,
            tenant_id=context.contract.principal.tenant_id,
            principal_id=context.contract.principal.user_id,
            principal_scopes=context.contract.principal.scopes,
            allowed_capabilities=context.contract.allowed_capabilities,
            data_scope=context.contract.data_scope.model_dump(mode="json"),
            correlation_id=context.correlation_id,
        )
