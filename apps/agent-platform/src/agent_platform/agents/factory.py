from __future__ import annotations

from typing import Any

from agents import Agent, ModelSettings, Tool
from openai.types.shared import Reasoning

from agent_platform.agents.model_router import ModelPolicy, ModelRoute
from agent_platform.agents.prompt_registry import PromptRegistry
from agent_platform.domain.enums import max_risk
from agent_platform.domain.models import (
    ExecutionPlan,
    TaskContract,
    TaskSpec,
    VerificationReport,
    WorkerOutput,
)
from agent_platform.tools.function_tools import AGENT_FUNCTION_TOOLS, AgentToolContext


class AgentFactory:
    def __init__(
        self,
        *,
        model_policy: ModelPolicy,
        prompts: PromptRegistry,
    ) -> None:
        self._models = model_policy
        self._prompts = prompts

    def planner(self, contract: TaskContract) -> Agent[AgentToolContext]:
        route = self._models.route("planner", contract.risk, 0, 0.7, contract.max_cost_usd)
        return Agent(
            name="planner",
            instructions=self._prompts.render(
                "planner",
                "1.0.0",
                {"contract": contract.model_dump(mode="json")},
            ),
            model=route.model,
            model_settings=self._settings(route),
            tools=[],
            output_type=ExecutionPlan,
        )

    def worker(
        self,
        contract: TaskContract,
        task: TaskSpec,
        retry_count: int,
    ) -> Agent[AgentToolContext]:
        route = self._models.route(
            "worker",
            max_risk(contract.risk, task.risk),
            retry_count,
            0.5,
            contract.max_cost_usd,
        )
        tools: list[Tool] = [
            AGENT_FUNCTION_TOOLS[name]
            for name in task.capability_names
            if name in AGENT_FUNCTION_TOOLS
        ]
        if any(getattr(tool, "name", "") == "commit_action" for tool in tools):
            raise ValueError("COMMIT_TOOL_NOT_AGENT_VISIBLE")
        return Agent(
            name=f"worker_{task.id}",
            instructions=self._prompts.render(
                "worker",
                "1.0.0",
                {
                    "contract": contract.model_dump(mode="json"),
                    "task": task.model_dump(mode="json"),
                },
            ),
            model=route.model,
            model_settings=self._settings(route),
            tools=tools,
            output_type=WorkerOutput,
        )

    def verifier(
        self,
        contract: TaskContract,
        deterministic_findings: dict[str, Any],
    ) -> Agent[AgentToolContext]:
        route = self._models.route("verifier", contract.risk, 0, 0.8, contract.max_cost_usd)
        return Agent(
            name="verifier",
            instructions=self._prompts.render(
                "verifier",
                "1.0.0",
                {
                    "contract": contract.model_dump(mode="json"),
                    "deterministic_findings": deterministic_findings,
                },
            ),
            model=route.model,
            model_settings=self._settings(route),
            tools=[],
            output_type=VerificationReport,
        )

    def audit_metadata(
        self,
        role: str,
        contract: TaskContract,
        *,
        task: TaskSpec | None = None,
        retry_count: int = 0,
    ) -> dict[str, Any]:
        if role == "planner":
            route = self._models.route(
                "planner",
                contract.risk,
                retry_count,
                0.7,
                contract.max_cost_usd,
            )
            prompt_id = "planner"
        elif role == "worker" and task is not None:
            route = self._models.route(
                "worker",
                max_risk(contract.risk, task.risk),
                retry_count,
                0.5,
                contract.max_cost_usd,
            )
            prompt_id = "worker"
        else:
            raise ValueError("AUDIT_RUNTIME_ROLE_UNSUPPORTED")
        return {
            "model_name": route.model,
            "model_settings": {
                "reasoning": route.reasoning,
                "max_output_tokens": route.max_output_tokens,
                "parallel_tool_calls": route.parallel_tool_calls,
                "store": False,
                "include_usage": True,
            },
            "prompt_id": prompt_id,
            "prompt_version": "1.0.0",
        }

    @staticmethod
    def _settings(route: ModelRoute) -> ModelSettings:
        return ModelSettings(
            reasoning=Reasoning.model_validate(route.reasoning),
            max_tokens=route.max_output_tokens,
            parallel_tool_calls=route.parallel_tool_calls,
            store=False,
            include_usage=True,
        )
