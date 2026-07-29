from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from pathlib import Path
from time import monotonic
from typing import Any, Protocol, cast

from agents import Agent, RunConfig, Runner, Tool
from agents.items import ModelResponse, TResponseInputItem
from agents.lifecycle import RunHooksBase
from agents.models.openai_provider import OpenAIProvider
from agents.run_context import RunContextWrapper
from openai import AsyncOpenAI

from agent_platform.agents.context_builder import (
    ContextAssembly,
    ContextAssemblyError,
    ContextBlock,
    ContextBuilder,
)
from agent_platform.agents.deterministic_runtime import RuntimeExecutionContext
from agent_platform.agents.factory import AgentFactory
from agent_platform.agents.model_reliability import ModelReliabilityRegistry
from agent_platform.agents.verification import deterministic_verification_findings
from agent_platform.application.dag_scheduler import BudgetLedger
from agent_platform.application.errors import PlatformError
from agent_platform.application.memory import MemoryContextReader
from agent_platform.application.trajectory_monitor import (
    TrajectoryCandidate,
    TrajectoryCheck,
    inspect_trajectory_content,
)
from agent_platform.domain.hashing import payload_hash
from agent_platform.domain.models import (
    ExecutionPlan,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
    validate_plan_against_contract,
)
from agent_platform.infrastructure.observability.runtime import RuntimeObservability
from agent_platform.tools.function_tools import AgentToolContext


class AgentRunResult(Protocol):
    final_output: object


@dataclass(frozen=True, slots=True)
class ModelUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0


@dataclass(frozen=True, slots=True)
class ModelPrice:
    input_usd_per_million_tokens: Decimal
    output_usd_per_million_tokens: Decimal
    cached_input_usd_per_million_tokens: Decimal | None = None

    def __post_init__(self) -> None:
        rates = (
            self.input_usd_per_million_tokens,
            self.output_usd_per_million_tokens,
            self.cached_input_usd_per_million_tokens,
        )
        if any(rate is not None and rate < 0 for rate in rates):
            raise ValueError("MODEL_PRICING_RATE_NEGATIVE")


@dataclass(frozen=True, slots=True)
class ModelPriceCatalog:
    catalog_version: str
    models: Mapping[str, ModelPrice]

    def __post_init__(self) -> None:
        if not self.catalog_version.strip() or not self.models:
            raise ValueError("MODEL_PRICING_CATALOG_INVALID")

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        allowed_models: tuple[str, ...],
    ) -> ModelPriceCatalog:
        raw_path = str(path).strip()
        if not raw_path:
            raise PlatformError(
                "MODEL_PRICING_CATALOG_REQUIRED",
                "A versioned model pricing catalog is required",
            )
        candidate = Path(raw_path)
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlatformError(
                "MODEL_PRICING_CATALOG_INVALID",
                "The versioned model pricing catalog could not be loaded",
                context={"path": str(candidate)},
            ) from exc
        if (
            not isinstance(raw, dict)
            or raw.get("schema_version") != "1.0"
            or raw.get("currency") != "USD"
            or not isinstance(raw.get("catalog_version"), str)
            or not isinstance(raw.get("models"), dict)
        ):
            raise PlatformError(
                "MODEL_PRICING_CATALOG_INVALID",
                "The model pricing catalog schema is invalid",
            )
        try:
            prices = {
                str(model): ModelPrice(
                    input_usd_per_million_tokens=Decimal(
                        str(values["input_usd_per_million_tokens"])
                    ),
                    output_usd_per_million_tokens=Decimal(
                        str(values["output_usd_per_million_tokens"])
                    ),
                    cached_input_usd_per_million_tokens=(
                        Decimal(str(values["cached_input_usd_per_million_tokens"]))
                        if "cached_input_usd_per_million_tokens" in values
                        else None
                    ),
                )
                for model, values in raw["models"].items()
                if isinstance(values, dict)
            }
            catalog = cls(
                catalog_version=raw["catalog_version"],
                models=prices,
            )
        except (InvalidOperation, KeyError, ValueError, TypeError) as exc:
            raise PlatformError(
                "MODEL_PRICING_CATALOG_INVALID",
                "The model pricing catalog contains an invalid rate",
            ) from exc
        for model in allowed_models:
            catalog.require_model(model)
        return catalog

    def require_model(self, model: str) -> ModelPrice:
        price = self.models.get(model)
        if price is None:
            raise PlatformError(
                "MODEL_PRICING_UNKNOWN",
                "The selected model has no approved pricing entry",
                context={
                    "model": model,
                    "pricing_catalog_version": self.catalog_version,
                },
            )
        return price

    def quote(self, model: str, usage: ModelUsage) -> Decimal:
        price = self.require_model(model)
        cached_tokens = min(usage.cached_input_tokens, usage.input_tokens)
        uncached_tokens = usage.input_tokens - cached_tokens
        cached_rate = (
            price.cached_input_usd_per_million_tokens
            if price.cached_input_usd_per_million_tokens is not None
            else price.input_usd_per_million_tokens
        )
        cost = (
            Decimal(uncached_tokens) * price.input_usd_per_million_tokens
            + Decimal(cached_tokens) * cached_rate
            + Decimal(usage.output_tokens) * price.output_usd_per_million_tokens
        ) / Decimal("1000000")
        if cost == 0:
            return Decimal("0")
        # The Run snapshot stores six decimal places. Round billable usage up so
        # repeated sub-micro-dollar calls cannot disappear from the hard limit.
        return cost.quantize(Decimal("0.000001"), rounding=ROUND_CEILING)


def _usage_from_object(usage: object | None) -> ModelUsage:
    if usage is None:
        return ModelUsage()
    details = getattr(usage, "input_tokens_details", None)
    return ModelUsage(
        input_tokens=OpenAIAgentRuntime._non_negative_int(getattr(usage, "input_tokens", 0)),
        output_tokens=OpenAIAgentRuntime._non_negative_int(getattr(usage, "output_tokens", 0)),
        cached_input_tokens=OpenAIAgentRuntime._non_negative_int(
            getattr(details, "cached_tokens", 0)
        ),
    )


class RuntimeBudgetHooks(RunHooksBase[AgentToolContext, Agent[AgentToolContext]]):
    """Enforce hard limits between SDK model turns and local tool calls."""

    def __init__(
        self,
        *,
        budget: BudgetLedger,
        pricing: ModelPriceCatalog,
        trajectory_guard: Any | None = None,
    ) -> None:
        self._budget = budget
        self._pricing = pricing
        self._trajectory = trajectory_guard
        self._model_checks: list[TrajectoryCheck] = []
        self.model_calls = 0

    async def on_llm_start(
        self,
        context: RunContextWrapper[AgentToolContext],
        agent: Agent[AgentToolContext],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        del system_prompt
        model = OpenAIAgentRuntime._model_name(agent)
        self._pricing.require_model(model)
        self._budget.assert_can_invoke("model")
        if self._trajectory is not None:
            runtime = context.context
            role = str(getattr(agent, "name", model))
            serialized_input = repr(input_items)
            signals = inspect_trajectory_content(input_items)
            data_scope = runtime.data_scope.model_dump(mode="json")
            check = await self._trajectory.preflight(
                run_id=runtime.run_id,
                tenant_id=runtime.principal.tenant_id,
                candidate=TrajectoryCandidate(
                    boundary="model",
                    task_id=runtime.task_id,
                    plan_version=runtime.plan_version,
                    operation_name=role,
                    args_hash=hashlib.sha256(serialized_input.encode("utf-8")).hexdigest(),
                    data_scope_hash=payload_hash(data_scope),
                    injection_indicators=signals.injection_indicators,
                    content_signal_hash=signals.content_signal_hash,
                    principal_id=runtime.principal.user_id,
                    principal_scopes=runtime.principal.scopes,
                    requested_data_scope=data_scope,
                ),
                correlation_id=runtime.correlation_id,
                actor_type="agent-model",
                actor_id=runtime.principal.user_id,
            )
            self._model_checks.append(check)

    async def on_llm_end(
        self,
        context: RunContextWrapper[AgentToolContext],
        agent: Agent[AgentToolContext],
        response: ModelResponse,
    ) -> None:
        del context
        model = OpenAIAgentRuntime._model_name(agent)
        usage = _usage_from_object(response.usage)
        self._budget.record_model_usage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost_usd=self._pricing.quote(model, usage),
            pricing_catalog_version=self._pricing.catalog_version,
        )
        if self._trajectory is not None and self._model_checks:
            check = self._model_checks.pop()
            await self._trajectory.record_outcome(check, status="succeeded")
        self.model_calls += 1

    async def on_tool_start(
        self,
        context: RunContextWrapper[AgentToolContext],
        agent: Agent[AgentToolContext],
        tool: Tool,
    ) -> None:
        del context, agent, tool
        self._budget.record_tool_call()


@dataclass(slots=True)
class OpenAIRuntimeContext:
    agent_context: AgentToolContext
    contract: TaskContract
    budget: BudgetLedger
    retry_count: int = 0


class SdkRunner:
    def __init__(self, *, client: AsyncOpenAI, store_model_content: bool) -> None:
        self._config = RunConfig(
            model_provider=OpenAIProvider(
                openai_client=client,
                use_responses=True,
                strict_feature_validation=True,
            ),
            tracing_disabled=False,
            trace_include_sensitive_data=store_model_content,
            workflow_name="bounded-agent-platform",
        )

    async def run(
        self,
        agent: Any,
        model_input: str,
        *,
        context: AgentToolContext,
        max_turns: int,
        hooks: RuntimeBudgetHooks,
    ) -> Any:
        return await Runner.run(
            agent,
            input=model_input,
            context=context,
            max_turns=max_turns,
            run_config=self._config,
            hooks=hooks,
        )


type AgentRuntimeContext = OpenAIRuntimeContext | RuntimeExecutionContext


class OpenAIAgentRuntime:
    def __init__(
        self,
        *,
        factory: AgentFactory,
        runner: Any,
        context_builder: ContextBuilder,
        known_capabilities: frozenset[str],
        pricing: ModelPriceCatalog,
        memory_vault: MemoryContextReader | None = None,
        trajectory_guard: Any | None = None,
        observability: RuntimeObservability | None = None,
        model_project_id: str = "development",
        model_reliability: ModelReliabilityRegistry | None = None,
    ) -> None:
        self._factory = factory
        self._runner = runner
        self._contexts = context_builder
        self._known_capabilities = known_capabilities
        self._pricing = pricing
        self._memory_vault = memory_vault
        self._trajectory = trajectory_guard
        self._observability = observability
        self._model_project_id = model_project_id
        self._model_reliability = model_reliability or ModelReliabilityRegistry()

    def audit_metadata(
        self,
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, Any]:
        return self._factory.audit_metadata(
            role,
            contract,
            task=task,
            retry_count=retry_count,
        )

    async def plan(self, context: AgentRuntimeContext, contract: TaskContract) -> ExecutionPlan:
        agent = self._factory.planner(contract)
        model_input = await self._contract_input(contract)
        result = await self._run_model(
            agent,
            model_input,
            context=self._agent_tool_context(
                context,
                task_id="planner",
                plan_version=0,
                allowed_capabilities=frozenset(),
            ),
            max_turns=2,
            role="planner",
            use_case=str(
                contract.constraints.get("use_case", contract.requested_output.schema_name)
            ),
            tenant_tier=str(contract.constraints.get("tenant_tier", "unknown")),
            budget=self._budget(context),
        )
        plan = ExecutionPlan.model_validate(result.final_output)
        validate_plan_against_contract(plan, contract, known_capabilities=self._known_capabilities)
        return plan

    async def execute_task(
        self,
        context: AgentRuntimeContext,
        task: TaskSpec,
        dependencies: dict[str, WorkerOutput],
    ) -> WorkerOutput:
        retry_count = context.retry_count if isinstance(context, OpenAIRuntimeContext) else 0
        agent = self._factory.worker(context.contract, task, retry_count)
        if retry_count > 0 and self._observability is not None:
            previous = self._factory.audit_metadata(
                "worker",
                context.contract,
                task=task,
                retry_count=retry_count - 1,
            )
            previous_model = str(previous["model_name"])
            current_model = self._model_name(agent)
            if previous_model != current_model:
                self._observability.record_model_upgrade(
                    role="worker",
                    from_model=previous_model,
                    to_model=current_model,
                    reason="retry",
                )
        blocks = [
            self._trusted_block(
                f"contract:{context.contract.schema_version}",
                context.contract.model_dump_json(),
                "task_contract",
            ),
            self._trusted_block(
                f"task:{task.id}",
                task.model_dump_json(),
                "assigned_task",
            ),
        ]
        blocks.extend(
            self._generated_block(
                f"dependency:{task_id}",
                output.model_dump_json(),
            )
            for task_id, output in dependencies.items()
        )
        blocks.extend(await self._memory_blocks(context.contract))
        assembled = self._contexts.assemble(
            blocks,
            allowed_uses=frozenset(
                {
                    "task_contract",
                    "assigned_task",
                    "dependency_data_only",
                    "long_term_memory",
                }
            ),
            required_uses=frozenset({"task_contract", "assigned_task"}),
        )
        result = await self._run_model(
            agent,
            self._model_input(assembled),
            context=self._agent_tool_context(
                context,
                task_id=task.id,
                plan_version=1,
                allowed_capabilities=(
                    frozenset(task.capability_names) & context.contract.allowed_capabilities
                ),
            ),
            max_turns=task.max_turns,
            role="worker",
            use_case=str(
                context.contract.constraints.get(
                    "use_case", context.contract.requested_output.schema_name
                )
            ),
            tenant_tier=str(context.contract.constraints.get("tenant_tier", "unknown")),
            budget=self._budget(context),
        )
        return WorkerOutput.model_validate(result.final_output)

    async def verify(
        self,
        context: AgentRuntimeContext,
        contract: TaskContract,
        plan: ExecutionPlan,
        outputs: dict[str, WorkerOutput],
    ) -> VerificationReport:
        deterministic = deterministic_verification_findings(contract, outputs)
        if deterministic["hard_failures"]:
            return VerificationReport(
                verdict=("escalate" if deterministic["requires_escalation"] else "revise"),
                failed_criteria=deterministic["failed_criteria"],
                unsupported_claim_ids=deterministic["unsupported_claim_ids"],
                missing_evidence=deterministic["hard_failures"],
                repair_instructions=[
                    "Repair deterministic evidence failures before semantic verification."
                ],
            )
        agent = self._factory.verifier(contract, deterministic)
        blocks = [
            self._trusted_block(
                "verification:contract",
                contract.model_dump_json(),
                "task_contract",
            ),
            self._trusted_block(
                "verification:plan",
                plan.model_dump_json(),
                "execution_plan",
            ),
            *[
                self._generated_block(
                    f"verification:output:{task_id}",
                    output.model_dump_json(),
                )
                for task_id, output in outputs.items()
            ],
        ]
        result = await self._run_model(
            agent,
            self._model_input(
                self._contexts.assemble(
                    blocks,
                    allowed_uses=frozenset(
                        {"task_contract", "execution_plan", "dependency_data_only"}
                    ),
                    required_uses=frozenset({"task_contract", "execution_plan"}),
                )
            ),
            context=self._agent_tool_context(
                context,
                task_id="verifier",
                plan_version=plan.plan_version,
                allowed_capabilities=frozenset(),
            ),
            max_turns=3,
            role="verifier",
            use_case=str(
                contract.constraints.get("use_case", contract.requested_output.schema_name)
            ),
            tenant_tier=str(contract.constraints.get("tenant_tier", "unknown")),
            budget=self._budget(context),
        )
        return VerificationReport.model_validate(result.final_output)

    async def _run_model(
        self,
        agent: object,
        model_input: str,
        *,
        context: AgentToolContext,
        max_turns: int,
        role: str,
        use_case: str = "unknown",
        tenant_tier: str = "unknown",
        budget: BudgetLedger | None = None,
    ) -> AgentRunResult:
        if budget is None:
            raise PlatformError(
                "BUDGET_CONTEXT_REQUIRED",
                "The model runtime requires a durable budget context",
            )
        model = self._model_name(agent)
        self._pricing.require_model(model)
        budget.assert_can_invoke("model")
        hooks = RuntimeBudgetHooks(
            budget=budget,
            pricing=self._pricing,
            trajectory_guard=self._trajectory,
        )
        started = monotonic()
        before_input = budget.usage.input_tokens
        before_output = budget.usage.output_tokens
        before_cost = budget.usage.cost_usd
        span = (
            self._observability.span(
                "agent.model.request",
                {
                    "correlation_id": context.correlation_id,
                    "run_id": str(context.run_id),
                    "plan_version": context.plan_version,
                    "task_id": context.task_id,
                    "tenant_id_hash": self._observability.tenant_hash(context.principal.tenant_id),
                    "role": role,
                    "model": model,
                },
            )
            if self._observability is not None
            else nullcontext()
        )

        async def invoke_provider() -> AgentRunResult:
            with span:
                run_kwargs = {
                    "context": context,
                    "max_turns": max_turns,
                }
                if self._runner_accepts_hooks():
                    run_kwargs["hooks"] = hooks
                result = cast(
                    AgentRunResult,
                    await self._runner.run(
                        agent,
                        model_input,
                        **run_kwargs,
                    ),
                )
                if hooks.model_calls == 0:
                    usage = self._extract_usage(result)
                    budget.record_model_usage(
                        input_tokens=usage.input_tokens,
                        output_tokens=usage.output_tokens,
                        cost_usd=self._pricing.quote(model, usage),
                        pricing_catalog_version=self._pricing.catalog_version,
                    )
                return result

        try:
            result = await self._model_reliability.call(
                self._model_project_id,
                model,
                invoke_provider,
            )
        except Exception:
            if self._observability is not None:
                self._observability.record_model(
                    role=role,
                    model=model,
                    status="error",
                    duration_seconds=monotonic() - started,
                    input_tokens=budget.usage.input_tokens - before_input,
                    output_tokens=budget.usage.output_tokens - before_output,
                    cost_usd=budget.usage.cost_usd - before_cost,
                    use_case=use_case,
                    tenant_tier=tenant_tier,
                )
            raise
        if self._observability is not None:
            observed_usage = self._extract_usage(result)
            self._observability.record_model(
                role=role,
                model=model,
                status="success",
                duration_seconds=monotonic() - started,
                input_tokens=budget.usage.input_tokens - before_input,
                output_tokens=budget.usage.output_tokens - before_output,
                cached_input_tokens=observed_usage.cached_input_tokens,
                cost_usd=budget.usage.cost_usd - before_cost,
                use_case=use_case,
                tenant_tier=tenant_tier,
            )
        return result

    @classmethod
    def _extract_usage(cls, result: object) -> ModelUsage:
        raw_responses = getattr(result, "raw_responses", ())
        if isinstance(raw_responses, (list, tuple)) and raw_responses:
            usages = [getattr(response, "usage", None) for response in raw_responses]
        else:
            direct_usage = getattr(result, "usage", None)
            if direct_usage is None:
                context_wrapper = getattr(result, "context_wrapper", None)
                direct_usage = getattr(context_wrapper, "usage", None)
            usages = [direct_usage]
        extracted = [_usage_from_object(usage) for usage in usages]
        return ModelUsage(
            input_tokens=sum(item.input_tokens for item in extracted),
            output_tokens=sum(item.output_tokens for item in extracted),
            cached_input_tokens=sum(item.cached_input_tokens for item in extracted),
        )

    def _runner_accepts_hooks(self) -> bool:
        try:
            parameters = inspect.signature(self._runner.run).parameters.values()
        except (TypeError, ValueError):
            return False
        return any(
            parameter.name == "hooks" or parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters
        )

    @staticmethod
    def _budget(context: AgentRuntimeContext) -> BudgetLedger:
        budget = getattr(context, "budget", None)
        if not isinstance(budget, BudgetLedger):
            raise PlatformError(
                "BUDGET_CONTEXT_REQUIRED",
                "The model runtime requires a durable budget context",
            )
        return budget

    @staticmethod
    def _non_negative_int(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return max(value, 0)

    @staticmethod
    def _model_name(agent: object) -> str:
        configured = getattr(agent, "model", None)
        if isinstance(configured, str) and configured:
            return configured
        for attribute in ("model", "model_name"):
            candidate = getattr(configured, attribute, None)
            if isinstance(candidate, str) and candidate:
                return candidate
        return "unknown"

    @staticmethod
    def _agent_tool_context(
        context: AgentRuntimeContext,
        *,
        task_id: str,
        plan_version: int,
        allowed_capabilities: frozenset[str],
    ) -> AgentToolContext:
        if isinstance(context, OpenAIRuntimeContext):
            return context.agent_context
        return AgentToolContext(
            run_id=context.run_id,
            task_id=task_id,
            plan_version=plan_version,
            principal=context.contract.principal,
            data_scope=context.contract.data_scope,
            allowed_capabilities=allowed_capabilities,
            correlation_id=context.correlation_id,
            gateway=context.gateway,
        )

    async def _contract_input(self, contract: TaskContract) -> str:
        blocks = [
            self._trusted_block(
                f"contract:{contract.schema_version}",
                contract.model_dump_json(),
                "task_contract",
            )
        ]
        blocks.extend(await self._memory_blocks(contract))
        assembled = self._contexts.assemble(
            blocks,
            allowed_uses=frozenset({"task_contract", "long_term_memory"}),
            required_uses=frozenset({"task_contract"}),
        )
        return self._model_input(assembled)

    async def _memory_blocks(self, contract: TaskContract) -> list[ContextBlock]:
        if "memory:read" not in contract.principal.scopes:
            return []
        if self._memory_vault is None:
            raise PlatformError(
                "MEMORY_CONTEXT_READER_REQUIRED",
                "Authorized long-term memory cannot be loaded without a configured reader",
                http_status=503,
            )
        purpose = self._memory_purpose(contract)
        try:
            memories = await self._memory_vault.list_for_context(
                tenant_id=contract.principal.tenant_id,
                principal_id=contract.principal.user_id,
                data_scope=contract.data_scope,
                purpose=purpose,
            )
        except PlatformError as exc:
            raise PlatformError(
                "MEMORY_CONTEXT_UNAVAILABLE",
                "Authorized long-term memory could not be loaded",
                retryable=exc.retryable,
                http_status=503,
                context={"cause_code": exc.code},
            ) from exc
        except Exception as exc:
            raise PlatformError(
                "MEMORY_CONTEXT_UNAVAILABLE",
                "Authorized long-term memory could not be loaded",
                retryable=True,
                http_status=503,
                context={"cause_type": type(exc).__name__},
            ) from exc
        return [
            ContextBlock(
                source_id=f"memory:{memory.memory_id}",
                source_time=memory.valid_from.isoformat(),
                source_version=f"memory-v{memory.version}",
                classification=memory.classification,
                owner=memory.owner_id,
                content_hash=memory.content_hash,
                trust="trusted/data",
                allowed_use="long_term_memory",
                content={
                    "memory_type": memory.memory_type,
                    "subject_type": memory.subject_type,
                    "subject_id": memory.subject_id,
                    "purpose": memory.purpose,
                    "source_refs": list(memory.source_refs),
                    "content": memory.content,
                },
            )
            for memory in memories
        ]

    @staticmethod
    def _memory_purpose(contract: TaskContract) -> str:
        for key in ("purpose", "use_case"):
            configured = contract.constraints.get(key)
            if isinstance(configured, str) and configured.strip():
                return configured.strip()
        return contract.requested_output.schema_name

    def _model_input(self, assembled: ContextAssembly) -> str:
        if not assembled.manifest["complete"]:
            raise ContextAssemblyError(
                "CONTEXT_ASSEMBLY_INCOMPLETE",
                "Model execution cannot continue with silently omitted context",
                context={
                    "manifest_hash": assembled.manifest["manifest_hash"],
                    "omitted_sources": assembled.manifest["omitted_sources"],
                },
            )
        return self._contexts.as_model_input(assembled)

    @staticmethod
    def _trusted_block(source_id: str, content: str, allowed_use: str) -> ContextBlock:
        return ContextBlock(
            source_id=source_id,
            source_time="application-generated",
            source_version="1.0",
            classification="internal",
            owner="agent-platform",
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
            trust="trusted/immutable",
            allowed_use=allowed_use,
            required=True,
            content=content,
        )

    @staticmethod
    def _generated_block(source_id: str, content: str) -> ContextBlock:
        return ContextBlock(
            source_id=source_id,
            source_time="application-generated",
            source_version="1.0",
            classification="internal",
            owner="bounded-agent",
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
            trust="untrusted/generated",
            allowed_use="dependency_data_only",
            content=content,
        )
