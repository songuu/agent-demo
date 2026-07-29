"""Authoritative, versioned domain values for bounded Agent execution."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from .base import JsonValue, StrictDomainModel, UtcDateTime
from .enums import (
    RISK_ORDER,
    ActionStatus,
    ApprovalDecision,
    DataClassification,
    RiskLevel,
    RunStatus,
    TrustLevel,
)
from .errors import DomainInvariantError
from .hashing import payload_hash

SHA256_PATTERN = r"^[0-9a-f]{64}$"
TASK_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"
CAPABILITY_PATTERN = r"^[a-z][a-z0-9_.:-]{0,127}$"

_RESERVED_ACTION_FIELDS = frozenset(
    {
        "action_id",
        "approval_policy",
        "approval_status",
        "credential_scope",
        "expires_at",
        "idempotency_key",
        "payload_hash",
        "policy",
        "policy_version",
        "principal_id",
        "required_approvals",
        "status",
        "tenant_id",
    }
)


def _duplicates[T](values: Iterable[T]) -> set[T]:
    seen: set[T] = set()
    duplicates: set[T] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _assert_no_reserved_action_fields(value: JsonValue, *, path: str = "parameters") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _RESERVED_ACTION_FIELDS:
                raise ValueError(
                    f"ACTION_PROPOSAL_RESERVED_FIELD: {path}.{key} is application-owned"
                )
            _assert_no_reserved_action_fields(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_no_reserved_action_fields(item, path=f"{path}[{index}]")


def _looks_like_commit_capability(name: str) -> bool:
    segments = name.lower().replace(":", ".").split(".")
    return "commit" in segments


class Principal(StrictDomainModel):
    user_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    roles: frozenset[str] = Field(default_factory=frozenset)
    scopes: frozenset[str] = Field(default_factory=frozenset)
    auth_strength: Literal["password", "mfa", "phishing_resistant"]
    delegation_id: str | None = Field(default=None, min_length=1, max_length=256)
    session_id: str | None = Field(default=None, min_length=1, max_length=256)


class DataScope(StrictDomainModel):
    tenant_id: str = Field(min_length=1, max_length=256)
    resource_types: frozenset[str] = Field(min_length=1)
    resource_ids: frozenset[str] = Field(default_factory=frozenset)
    row_filter: dict[str, JsonValue] = Field(default_factory=dict)
    allowed_fields: frozenset[str] = Field(default_factory=frozenset)
    classifications: frozenset[DataClassification] = Field(
        default_factory=lambda: frozenset({DataClassification.INTERNAL}),
        min_length=1,
    )

    def is_subset_of(self, other: DataScope) -> bool:
        if self.tenant_id != other.tenant_id:
            return False
        if not self.resource_types <= other.resource_types:
            return False
        if other.resource_ids and not self.resource_ids <= other.resource_ids:
            return False
        if other.allowed_fields and not self.allowed_fields <= other.allowed_fields:
            return False
        return self.classifications <= other.classifications


class SuccessCriterion(StrictDomainModel):
    id: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=4_000)
    severity: Literal["must", "should"] = "must"
    verification: Literal["schema", "evidence", "environment", "human"]
    evidence_required: bool = False


class OutputContract(StrictDomainModel):
    schema_name: str = Field(default="FinalResponse@1.0", min_length=1, max_length=256)
    media_type: str = Field(default="application/json", min_length=1, max_length=256)
    artifact_required: bool = False
    max_bytes: int = Field(default=1_048_576, ge=1, le=100 * 1024 * 1024)


class TaskContract(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    goal: str = Field(min_length=1, max_length=10_000)
    success_criteria: list[SuccessCriterion] = Field(min_length=1, max_length=50)
    principal: Principal
    data_scope: DataScope
    risk: RiskLevel
    allowed_capabilities: frozenset[str] = Field(default_factory=frozenset)
    constraints: dict[str, JsonValue] = Field(default_factory=dict)
    max_cost_usd: Decimal = Field(gt=0, max_digits=14, decimal_places=4)
    max_duration_seconds: int = Field(ge=5, le=86_400)
    max_tool_calls: int = Field(default=100, ge=0, le=10_000)
    max_parallelism: int = Field(default=3, ge=1, le=16)
    max_replans: int = Field(default=2, ge=0, le=5)
    external_write_policy: Literal["deny", "prepare_only", "approval"] = "deny"
    requested_output: OutputContract = Field(default_factory=OutputContract)

    @model_validator(mode="after")
    def validate_authority_boundary(self) -> Self:
        if self.principal.tenant_id != self.data_scope.tenant_id:
            raise ValueError(
                "TASK_CONTRACT_TENANT_MISMATCH: "
                f"principal tenant {self.principal.tenant_id!r} does not match "
                f"data scope tenant {self.data_scope.tenant_id!r}"
            )
        duplicate_criteria = _duplicates(item.id for item in self.success_criteria)
        if duplicate_criteria:
            raise ValueError(
                f"TASK_CONTRACT_DUPLICATE_CRITERION: duplicate ids {sorted(duplicate_criteria)!r}"
            )
        commit_capabilities = sorted(
            name for name in self.allowed_capabilities if _looks_like_commit_capability(name)
        )
        if commit_capabilities:
            raise ValueError(
                "TASK_CONTRACT_COMMIT_CAPABILITY_FORBIDDEN: "
                f"Agent-visible capabilities cannot commit: {commit_capabilities!r}"
            )
        return self


class ArtifactRef(StrictDomainModel):
    artifact_id: UUID
    uri: str | None = Field(default=None, min_length=1, max_length=2_048)
    sha256: str = Field(pattern=SHA256_PATTERN)
    classification: DataClassification
    kind: str | None = Field(default=None, min_length=1, max_length=128)
    media_type: str | None = Field(default=None, min_length=1, max_length=256)
    size_bytes: int | None = Field(default=None, ge=0)


class SourceRef(StrictDomainModel):
    source_type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=1_024)
    version: str | None = Field(default=None, min_length=1, max_length=256)
    uri: str | None = Field(default=None, min_length=1, max_length=2_048)
    trust: TrustLevel = TrustLevel.UNTRUSTED
    content_hash: str | None = Field(default=None, pattern=SHA256_PATTERN)


class Artifact(StrictDomainModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    tenant_id: str = Field(min_length=1, max_length=256)
    run_id: UUID
    task_id: str | None = Field(default=None, pattern=TASK_ID_PATTERN)
    kind: Literal["tool_result", "document", "report", "code", "receipt", "trace_export"]
    uri: str = Field(min_length=1, max_length=2_048)
    media_type: str = Field(min_length=1, max_length=256)
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    classification: DataClassification
    source: SourceRef
    created_by: str = Field(min_length=1, max_length=256)
    retention_policy: str = Field(min_length=1, max_length=256)
    expires_at: UtcDateTime | None = None
    encryption_key_ref: str | None = Field(default=None, min_length=1, max_length=1_024)

    def ref(self) -> ArtifactRef:
        return ArtifactRef(
            artifact_id=self.artifact_id,
            uri=self.uri,
            sha256=self.sha256,
            classification=self.classification,
            kind=self.kind,
            media_type=self.media_type,
            size_bytes=self.size_bytes,
        )


class TaskSpec(StrictDomainModel):
    id: str = Field(pattern=TASK_ID_PATTERN)
    kind: Literal["research", "analysis", "code", "synthesis", "verify"]
    objective: str = Field(min_length=1, max_length=10_000)
    depends_on: list[str] = Field(default_factory=list, max_length=50)
    capability_names: list[str] = Field(default_factory=list, max_length=50)
    input_refs: list[ArtifactRef] = Field(default_factory=list, max_length=100)
    output_schema: str = Field(min_length=1, max_length=256)
    risk: RiskLevel
    max_turns: int = Field(default=6, ge=1, le=20)
    timeout_seconds: int = Field(default=90, ge=5, le=1_800)
    max_tool_calls: int = Field(default=12, ge=0, le=100)
    estimated_cost_usd: Decimal = Field(
        default=Decimal("0"),
        ge=0,
        max_digits=14,
        decimal_places=4,
    )
    approval_boundary: Literal["none", "prepare_only"] = "none"

    @field_validator("capability_names")
    @classmethod
    def validate_capability_names(cls, values: list[str]) -> list[str]:
        duplicates = _duplicates(values)
        if duplicates:
            raise ValueError(f"TASK_DUPLICATE_CAPABILITY: duplicate names {sorted(duplicates)!r}")
        for name in values:
            if not name or len(name) > 128:
                raise ValueError(f"TASK_CAPABILITY_NAME_INVALID: invalid capability name {name!r}")
            if _looks_like_commit_capability(name):
                raise ValueError(
                    f"TASK_COMMIT_CAPABILITY_FORBIDDEN: {name!r} cannot be Agent-visible"
                )
        return values

    @model_validator(mode="after")
    def validate_dependencies(self) -> Self:
        duplicates = _duplicates(self.depends_on)
        if duplicates:
            raise ValueError(
                f"TASK_DUPLICATE_DEPENDENCY: {self.id!r} repeats {sorted(duplicates)!r}"
            )
        if self.id in self.depends_on:
            raise ValueError(f"TASK_SELF_DEPENDENCY: {self.id!r} depends on itself")
        return self


class ExecutionPlan(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    plan_id: UUID = Field(default_factory=uuid4)
    plan_version: int = Field(ge=1)
    assumptions: list[str] = Field(default_factory=list, max_length=100)
    tasks: list[TaskSpec] = Field(min_length=1, max_length=50)
    final_task_id: str = Field(pattern=TASK_ID_PATTERN)
    expected_total_cost_usd: Decimal = Field(ge=0, max_digits=14, decimal_places=4)

    @model_validator(mode="after")
    def validate_dag(self) -> Self:
        by_id = {task.id: task for task in self.tasks}
        if len(by_id) != len(self.tasks):
            duplicates = sorted(_duplicates(task.id for task in self.tasks))
            raise ValueError(f"PLAN_DUPLICATE_TASK_ID: duplicate ids {duplicates!r}")
        if self.final_task_id not in by_id:
            raise ValueError(
                f"PLAN_FINAL_TASK_MISSING: final task {self.final_task_id!r} does not exist"
            )
        for task in self.tasks:
            unknown = sorted(set(task.depends_on) - set(by_id))
            if unknown:
                raise ValueError(
                    "PLAN_UNKNOWN_DEPENDENCY: "
                    f"task {task.id!r} references unknown dependencies {unknown!r}"
                )

        visiting: list[str] = []
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                start = visiting.index(task_id)
                cycle = [*visiting[start:], task_id]
                raise ValueError(f"PLAN_DEPENDENCY_CYCLE: {' -> '.join(cycle)}")
            if task_id in visited:
                return
            visiting.append(task_id)
            for dependency in by_id[task_id].depends_on:
                visit(dependency)
            visiting.pop()
            visited.add(task_id)

        for task_id in by_id:
            visit(task_id)

        consumers = [task.id for task in self.tasks if self.final_task_id in task.depends_on]
        if consumers:
            raise ValueError(
                f"PLAN_FINAL_TASK_NOT_SINK: {self.final_task_id!r} is consumed by {consumers!r}"
            )
        task_cost = sum(
            (task.estimated_cost_usd for task in self.tasks),
            start=Decimal("0"),
        )
        if self.expected_total_cost_usd != task_cost:
            raise ValueError(
                "PLAN_COST_MISMATCH: "
                f"declared {self.expected_total_cost_usd} but tasks total {task_cost}"
            )
        return self

    def critical_path_seconds(self) -> int:
        by_id = {task.id: task for task in self.tasks}
        memo: dict[str, int] = {}

        def duration(task_id: str) -> int:
            if task_id not in memo:
                task = by_id[task_id]
                dependency_duration = max(
                    (duration(dependency) for dependency in task.depends_on),
                    default=0,
                )
                memo[task_id] = dependency_duration + task.timeout_seconds
            return memo[task_id]

        return max(duration(task.id) for task in self.tasks)

    def parallel_width(self) -> int:
        """Return the maximum DAG antichain using the standard bipartite reduction."""
        by_id = {task.id: task for task in self.tasks}
        reachable: dict[str, set[str]] = {}

        def descendants(task_id: str) -> set[str]:
            if task_id in reachable:
                return reachable[task_id]
            result: set[str] = set()
            for candidate in self.tasks:
                if task_id in candidate.depends_on:
                    result.add(candidate.id)
                    result.update(descendants(candidate.id))
            reachable[task_id] = result
            return result

        for task_id in by_id:
            descendants(task_id)

        matched_right: dict[str, str] = {}

        def augment(left: str, visited_right: set[str]) -> bool:
            for right in sorted(reachable[left]):
                if right in visited_right:
                    continue
                visited_right.add(right)
                owner = matched_right.get(right)
                if owner is None or augment(owner, visited_right):
                    matched_right[right] = left
                    return True
            return False

        matching = sum(1 for task_id in sorted(by_id) if augment(task_id, set()))
        return len(by_id) - matching


def validate_plan_against_contract(
    plan: ExecutionPlan,
    contract: TaskContract,
    *,
    known_capabilities: set[str] | frozenset[str] | None = None,
) -> None:
    """Apply deterministic authorization, budget, duration, and risk gates."""
    for task in plan.tasks:
        for capability in task.capability_names:
            known = known_capabilities is None or capability in known_capabilities
            allowed = capability in contract.allowed_capabilities
            if not known or not allowed:
                raise DomainInvariantError(
                    "PLAN_CAPABILITY_NOT_ALLOWED",
                    "task requested an unknown or unauthorized capability",
                    context={
                        "task_id": task.id,
                        "capability": capability,
                        "known": known,
                        "allowed": allowed,
                    },
                )
        for ref in task.input_refs:
            if ref.classification not in contract.data_scope.classifications:
                raise DomainInvariantError(
                    "PLAN_DATA_SCOPE_DENIED",
                    "task input classification exceeds the contract data scope",
                    context={
                        "task_id": task.id,
                        "artifact_id": str(ref.artifact_id),
                        "classification": ref.classification.value,
                    },
                )

    if plan.expected_total_cost_usd > contract.max_cost_usd:
        raise DomainInvariantError(
            "BUDGET_EXHAUSTED",
            "planned cost exceeds the contract budget",
            context={
                "planned_cost_usd": str(plan.expected_total_cost_usd),
                "max_cost_usd": str(contract.max_cost_usd),
            },
        )
    critical_path = plan.critical_path_seconds()
    if critical_path > contract.max_duration_seconds:
        raise DomainInvariantError(
            "PLAN_DURATION_EXCEEDED",
            "critical path exceeds the contract duration",
            context={
                "critical_path_seconds": critical_path,
                "max_duration_seconds": contract.max_duration_seconds,
            },
        )
    parallel_width = plan.parallel_width()
    if parallel_width > contract.max_parallelism:
        raise DomainInvariantError(
            "PLAN_PARALLELISM_EXCEEDED",
            "DAG permits more concurrent work than the contract",
            context={
                "parallel_width": parallel_width,
                "max_parallelism": contract.max_parallelism,
            },
        )
    plan_risk = max((task.risk for task in plan.tasks), key=RISK_ORDER.__getitem__)
    final_risk = next(task.risk for task in plan.tasks if task.id == plan.final_task_id)
    if (
        RISK_ORDER[plan_risk] < RISK_ORDER[contract.risk]
        or RISK_ORDER[final_risk] < RISK_ORDER[contract.risk]
    ):
        raise DomainInvariantError(
            "PLAN_RISK_DOWNGRADE",
            "plan or final task risk is lower than the authoritative contract",
            context={
                "contract_risk": contract.risk.value,
                "plan_risk": plan_risk.value,
                "final_task_risk": final_risk.value,
            },
        )


class Evidence(StrictDomainModel):
    evidence_id: UUID = Field(default_factory=uuid4)
    source_type: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=1_024)
    locator: str | None = Field(default=None, min_length=1, max_length=2_048)
    captured_at: UtcDateTime
    content_hash: str = Field(pattern=SHA256_PATTERN)
    supports_claim_ids: list[str] = Field(default_factory=list, max_length=100)
    supports_criterion_ids: list[str] = Field(default_factory=list, max_length=50)
    trust: TrustLevel

    @field_validator("supports_claim_ids")
    @classmethod
    def unique_claim_links(cls, values: list[str]) -> list[str]:
        duplicates = _duplicates(values)
        if duplicates:
            raise ValueError(f"EVIDENCE_DUPLICATE_CLAIM_LINK: duplicate ids {sorted(duplicates)!r}")
        return values

    @field_validator("supports_criterion_ids")
    @classmethod
    def unique_criterion_links(cls, values: list[str]) -> list[str]:
        duplicates = _duplicates(values)
        if duplicates:
            raise ValueError(
                f"EVIDENCE_DUPLICATE_CRITERION_LINK: duplicate ids {sorted(duplicates)!r}"
            )
        return values

    @model_validator(mode="after")
    def validate_support_link_exists(self) -> Self:
        if not self.supports_claim_ids and not self.supports_criterion_ids:
            raise ValueError(
                "EVIDENCE_SUPPORT_LINK_REQUIRED: evidence must support a claim or criterion"
            )
        return self


class CriterionVerification(StrictDomainModel):
    """Application-verifiable result for one immutable success criterion."""

    criterion_id: str = Field(min_length=1, max_length=128)
    method: Literal["schema", "evidence", "environment", "human"]
    passed: bool
    checked_at: UtcDateTime
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=100)
    failure_reason: str | None = Field(default=None, min_length=1, max_length=4_000)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    verifier_version: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_links(cls, values: list[UUID]) -> list[UUID]:
        duplicates = _duplicates(values)
        if duplicates:
            raise ValueError(
                "CRITERION_VERIFICATION_DUPLICATE_EVIDENCE: "
                f"duplicate ids {[str(item) for item in sorted(duplicates, key=str)]!r}"
            )
        return values

    @model_validator(mode="after")
    def validate_result_is_auditable(self) -> Self:
        if (
            self.passed
            and self.method in {"evidence", "environment", "human"}
            and not self.evidence_ids
        ):
            raise ValueError(
                "CRITERION_VERIFICATION_EVIDENCE_REQUIRED: "
                f"passed {self.method} verification requires evidence"
            )
        if not self.passed and self.failure_reason is None:
            raise ValueError(
                "CRITERION_VERIFICATION_FAILURE_REASON_REQUIRED: "
                "failed verification requires a reason"
            )
        return self


class Claim(StrictDomainModel):
    claim_id: str = Field(min_length=1, max_length=128)
    statement: str = Field(min_length=1, max_length=10_000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[UUID] = Field(min_length=1, max_length=100)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence_links(cls, values: list[UUID]) -> list[UUID]:
        duplicates = _duplicates(values)
        if duplicates:
            raise ValueError(
                "CLAIM_DUPLICATE_EVIDENCE_LINK: "
                f"duplicate ids {[str(item) for item in sorted(duplicates, key=str)]!r}"
            )
        return values


def _validate_claim_evidence(
    claims: list[Claim],
    evidence: list[Evidence],
    *,
    prefix: str,
) -> None:
    duplicate_claims = _duplicates(claim.claim_id for claim in claims)
    if duplicate_claims:
        raise ValueError(f"{prefix}_DUPLICATE_CLAIM: duplicate ids {sorted(duplicate_claims)!r}")
    duplicate_evidence = _duplicates(item.evidence_id for item in evidence)
    if duplicate_evidence:
        raise ValueError(
            f"{prefix}_DUPLICATE_EVIDENCE: "
            f"duplicate ids {[str(item) for item in sorted(duplicate_evidence, key=str)]!r}"
        )
    claims_by_id = {claim.claim_id: claim for claim in claims}
    evidence_by_id = {item.evidence_id: item for item in evidence}
    for claim in claims:
        for evidence_id in claim.evidence_ids:
            item = evidence_by_id.get(evidence_id)
            if item is None:
                raise ValueError(
                    f"{prefix}_UNKNOWN_EVIDENCE: claim {claim.claim_id!r} "
                    f"references {str(evidence_id)!r}"
                )
            if claim.claim_id not in item.supports_claim_ids:
                raise ValueError(
                    f"{prefix}_NONRECIPROCAL_LINK: evidence {str(evidence_id)!r} "
                    f"does not support claim {claim.claim_id!r}"
                )
    for item in evidence:
        for claim_id in item.supports_claim_ids:
            linked_claim = claims_by_id.get(claim_id)
            if linked_claim is None:
                raise ValueError(
                    f"{prefix}_UNKNOWN_CLAIM: evidence {str(item.evidence_id)!r} "
                    f"references {claim_id!r}"
                )
            if item.evidence_id not in linked_claim.evidence_ids:
                raise ValueError(
                    f"{prefix}_NONRECIPROCAL_LINK: claim {claim_id!r} "
                    f"does not reference evidence {str(item.evidence_id)!r}"
                )


def _validate_criterion_evidence(
    verifications: list[CriterionVerification],
    evidence: list[Evidence],
    *,
    prefix: str,
) -> None:
    duplicate_criteria = _duplicates(item.criterion_id for item in verifications)
    if duplicate_criteria:
        raise ValueError(
            f"{prefix}_DUPLICATE_CRITERION_VERIFICATION: "
            f"duplicate ids {sorted(duplicate_criteria)!r}"
        )
    evidence_by_id = {item.evidence_id: item for item in evidence}
    verifications_by_id = {item.criterion_id: item for item in verifications}
    for verification in verifications:
        missing = set(verification.evidence_ids) - set(evidence_by_id)
        if missing:
            raise ValueError(
                f"{prefix}_UNKNOWN_CRITERION_EVIDENCE: "
                f"criterion {verification.criterion_id!r} references "
                f"{[str(item) for item in sorted(missing, key=str)]!r}"
            )
        for evidence_id in verification.evidence_ids:
            item = evidence_by_id[evidence_id]
            if verification.criterion_id not in item.supports_criterion_ids:
                raise ValueError(
                    f"{prefix}_NONRECIPROCAL_CRITERION_LINK: "
                    f"evidence {str(evidence_id)!r} does not support criterion "
                    f"{verification.criterion_id!r}"
                )
    for item in evidence:
        for criterion_id in item.supports_criterion_ids:
            linked_verification = verifications_by_id.get(criterion_id)
            if linked_verification is None:
                raise ValueError(
                    f"{prefix}_UNKNOWN_CRITERION: evidence {str(item.evidence_id)!r} "
                    f"references {criterion_id!r}"
                )
            if item.evidence_id not in linked_verification.evidence_ids:
                raise ValueError(
                    f"{prefix}_NONRECIPROCAL_CRITERION_LINK: "
                    f"criterion {criterion_id!r} does not reference evidence "
                    f"{str(item.evidence_id)!r}"
                )


class ActionProposal(StrictDomainModel):
    action_type: str = Field(min_length=1, max_length=256)
    parameters: dict[str, JsonValue]
    rationale: str = Field(min_length=1, max_length=10_000)
    expected_effect: str = Field(min_length=1, max_length=10_000)

    @model_validator(mode="before")
    @classmethod
    def reject_application_owned_fields(cls, value: JsonValue) -> JsonValue:
        if isinstance(value, dict):
            parameters = value.get("parameters")
            if isinstance(parameters, dict):
                _assert_no_reserved_action_fields(parameters)
        return value


class WorkerOutput(StrictDomainModel):
    summary: str = Field(min_length=1, max_length=20_000)
    claims: list[Claim] = Field(default_factory=list, max_length=200)
    evidence: list[Evidence] = Field(default_factory=list, max_length=500)
    criterion_verifications: list[CriterionVerification] = Field(
        default_factory=list,
        max_length=50,
    )
    artifacts: list[UUID] = Field(default_factory=list, max_length=100)
    action_proposals: list[ActionProposal] = Field(default_factory=list, max_length=50)
    uncertainties: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_claim_evidence_links(self) -> Self:
        _validate_claim_evidence(self.claims, self.evidence, prefix="WORKER_OUTPUT")
        _validate_criterion_evidence(
            self.criterion_verifications,
            self.evidence,
            prefix="WORKER_OUTPUT",
        )
        if _duplicates(self.artifacts):
            raise ValueError("WORKER_OUTPUT_DUPLICATE_ARTIFACT: artifact ids must be unique")
        return self


class VerificationReport(StrictDomainModel):
    verdict: Literal["pass", "revise", "escalate"]
    failed_criteria: list[str] = Field(default_factory=list)
    unsupported_claim_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    risk_findings: list[str] = Field(default_factory=list)
    repair_instructions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_pass_is_clean(self) -> Self:
        findings = (
            self.failed_criteria,
            self.unsupported_claim_ids,
            self.missing_evidence,
            self.risk_findings,
            self.repair_instructions,
        )
        if self.verdict == "pass" and any(findings):
            raise ValueError(
                "VERIFICATION_PASS_WITH_FINDINGS: pass cannot retain unresolved findings"
            )
        if self.verdict == "revise" and not self.repair_instructions:
            raise ValueError(
                "VERIFICATION_REPAIR_REQUIRED: revise must include repair instructions"
            )
        return self


class VerificationResult(StrictDomainModel):
    passed: bool
    verified_at: UtcDateTime
    method: str = Field(min_length=1, max_length=256)
    details: dict[str, JsonValue] = Field(default_factory=dict)
    verifier_version: str | None = Field(default=None, min_length=1, max_length=256)


class ActionPreview(StrictDomainModel):
    summary: str = Field(min_length=1, max_length=10_000)
    target: str | None = Field(default=None, min_length=1, max_length=2_048)
    normalized_parameters: dict[str, JsonValue] = Field(default_factory=dict)
    diff: dict[str, JsonValue] = Field(default_factory=dict)
    expected_effects: list[str] = Field(default_factory=list, max_length=100)
    artifact_refs: list[ArtifactRef] = Field(default_factory=list, max_length=100)
    estimated_cost_usd: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=14,
        decimal_places=4,
    )
    classification: DataClassification = DataClassification.INTERNAL


class PreparedActionView(StrictDomainModel):
    action_id: UUID
    action_type: str
    preview: ActionPreview
    risk: RiskLevel
    status: ActionStatus
    payload_hash: str
    expires_at: UtcDateTime


class PreparedAction(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    action_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    tenant_id: str = Field(min_length=1, max_length=256)
    principal_id: str = Field(min_length=1, max_length=256)
    action_type: str = Field(min_length=1, max_length=256)
    tool_name: str = Field(min_length=1, max_length=256)
    tool_version: str = Field(min_length=1, max_length=128)
    canonical_payload: dict[str, JsonValue]
    payload_hash: str = Field(pattern=SHA256_PATTERN)
    preview: ActionPreview
    risk: RiskLevel
    approval_policy: str = Field(min_length=1, max_length=256)
    required_approvals: int = Field(default=1, ge=0, le=10)
    require_initiator_separation: bool = False
    required_approver_roles: frozenset[str] = Field(default_factory=frozenset)
    minimum_auth_strength: Literal["password", "mfa", "phishing_resistant"] = "mfa"
    status: ActionStatus
    idempotency_key: str = Field(min_length=1, max_length=512)
    policy_version: str = Field(min_length=1, max_length=256)
    expires_at: UtcDateTime
    created_at: UtcDateTime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_trusted_action(self) -> Self:
        computed = payload_hash(self.canonical_payload)
        if self.payload_hash != computed:
            raise ValueError(
                "ACTION_PAYLOAD_HASH_MISMATCH: "
                f"declared {self.payload_hash!r} does not match canonical payload {computed!r}"
            )
        if self.preview.normalized_parameters != self.canonical_payload:
            raise ValueError(
                "ACTION_PREVIEW_PAYLOAD_MISMATCH: preview must render canonical parameters"
            )
        if self.risk is RiskLevel.CRITICAL and self.required_approvals < 2:
            raise ValueError(
                "CRITICAL_ACTION_MULTI_APPROVAL_REQUIRED: at least two approvers are required"
            )
        if self.status is ActionStatus.PENDING_APPROVAL and self.required_approvals < 1:
            raise ValueError(
                "ACTION_APPROVAL_COUNT_REQUIRED: pending approval requires an approver"
            )
        return self

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    def public_view(self) -> PreparedActionView:
        return PreparedActionView(
            action_id=self.action_id,
            action_type=self.action_type,
            preview=self.preview,
            risk=self.risk,
            status=self.status,
            payload_hash=self.payload_hash,
            expires_at=self.expires_at,
        )


class ApprovalRecord(StrictDomainModel):
    approval_id: UUID = Field(default_factory=uuid4)
    action_id: UUID
    actor_id: str = Field(min_length=1, max_length=256)
    actor_roles: frozenset[str] = Field(default_factory=frozenset)
    auth_strength: Literal["password", "mfa", "phishing_resistant"]
    decision: ApprovalDecision
    comment: str | None = Field(default=None, max_length=4_000)
    policy_version: str = Field(min_length=1, max_length=256)
    payload_hash: str = Field(pattern=SHA256_PATTERN)
    decided_at: UtcDateTime


class CommitReceipt(StrictDomainModel):
    external_operation_id: str | None = Field(default=None, min_length=1, max_length=1_024)
    committed_at: UtcDateTime
    result_summary: dict[str, JsonValue]
    raw_receipt_artifact_id: UUID | None = None
    idempotency_key: str = Field(min_length=1, max_length=512)
    verification: VerificationResult | None = None
    provider_request_id: str | None = Field(default=None, min_length=1, max_length=1_024)


class CompensationReceipt(StrictDomainModel):
    external_operation_id: str | None = Field(default=None, min_length=1, max_length=1_024)
    compensated_at: UtcDateTime
    result_summary: dict[str, JsonValue]
    original_idempotency_key: str = Field(min_length=1, max_length=512)
    verification: VerificationResult


class FinalResponse(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    summary: str = Field(min_length=1, max_length=20_000)
    claims: list[Claim] = Field(default_factory=list, max_length=200)
    evidence: list[Evidence] = Field(default_factory=list, max_length=500)
    criterion_verifications: list[CriterionVerification] = Field(
        default_factory=list,
        max_length=50,
    )
    artifacts: list[ArtifactRef] = Field(default_factory=list, max_length=100)
    receipts: list[CommitReceipt] = Field(default_factory=list, max_length=100)
    caveats: list[str] = Field(default_factory=list, max_length=100)
    incomplete_items: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def validate_verified_only(self) -> Self:
        _validate_claim_evidence(self.claims, self.evidence, prefix="FINAL_RESPONSE")
        _validate_criterion_evidence(
            self.criterion_verifications,
            self.evidence,
            prefix="FINAL_RESPONSE",
        )
        for receipt in self.receipts:
            if receipt.verification is None or not receipt.verification.passed:
                raise ValueError(
                    "FINAL_RESPONSE_UNVERIFIED_RECEIPT: "
                    f"idempotency key {receipt.idempotency_key!r} is not verified"
                )
        duplicate_artifacts = _duplicates(item.artifact_id for item in self.artifacts)
        if duplicate_artifacts:
            raise ValueError("FINAL_RESPONSE_DUPLICATE_ARTIFACT: artifact ids must be unique")
        duplicate_receipts = _duplicates(item.idempotency_key for item in self.receipts)
        if duplicate_receipts:
            raise ValueError("FINAL_RESPONSE_DUPLICATE_RECEIPT: idempotency keys must be unique")
        return self


class MemoryCandidate(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    candidate_id: UUID = Field(default_factory=uuid4)
    subject_type: Literal["user", "project", "tenant", "run", "artifact"]
    subject_id: str = Field(min_length=1, max_length=1_024)
    memory_type: str = Field(min_length=1, max_length=128)
    content: dict[str, JsonValue]
    source_refs: list[str] = Field(default_factory=list, max_length=100)
    classification: DataClassification
    confidence: Decimal = Field(ge=0, le=1, max_digits=5, decimal_places=4)
    purpose: str = Field(min_length=1, max_length=4_000)
    owner_id: str = Field(min_length=1, max_length=256)
    write_policy: Literal["deny", "automatic", "explicit_approval"]
    user_visible: bool
    trust: TrustLevel = TrustLevel.GENERATED
    conflict_policy: Literal["reject", "supersede", "merge", "human_review"] = "human_review"
    expires_at: UtcDateTime | None = None
    created_at: UtcDateTime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_memory_boundary(self) -> Self:
        sensitive = self.classification in {
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
            DataClassification.SECRET,
        }
        if sensitive and self.expires_at is None:
            raise ValueError("MEMORY_RETENTION_REQUIRED: sensitive memory needs an explicit expiry")
        if (
            self.classification in {DataClassification.RESTRICTED, DataClassification.SECRET}
            and self.write_policy != "explicit_approval"
        ):
            raise ValueError(
                "MEMORY_EXPLICIT_APPROVAL_REQUIRED: restricted memory cannot be automatic"
            )
        if not self.source_refs and self.write_policy != "explicit_approval":
            raise ValueError("MEMORY_PROVENANCE_REQUIRED: automatic memory needs source references")
        if self.subject_type == "user" and not self.user_visible:
            raise ValueError("MEMORY_USER_VISIBILITY_REQUIRED: user-profile memory must be visible")
        if _duplicates(self.source_refs):
            raise ValueError("MEMORY_DUPLICATE_SOURCE: source references must be unique")
        return self


class RunSnapshot(StrictDomainModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: UUID
    tenant_id: str = Field(min_length=1, max_length=256)
    status: RunStatus
    version: int = Field(ge=1)
    contract: TaskContract
    plan: ExecutionPlan | None = None
    progress: float = Field(default=0, ge=0, le=1)
    cost_actual_usd: Decimal = Field(default=Decimal("0"), ge=0)
    created_at: UtcDateTime
    updated_at: UtcDateTime
    completed_at: UtcDateTime | None = None

    @model_validator(mode="after")
    def validate_snapshot_tenant_and_terminal_time(self) -> Self:
        if self.tenant_id != self.contract.principal.tenant_id:
            raise ValueError("RUN_SNAPSHOT_TENANT_MISMATCH: run and contract tenants differ")
        terminal = {
            RunStatus.COMPLETED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        }
        if (self.status in terminal) != (self.completed_at is not None):
            raise ValueError(
                "RUN_SNAPSHOT_COMPLETION_TIME_MISMATCH: terminal status and completed_at must agree"
            )
        return self
