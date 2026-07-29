"""Tenant- and task-authorized Tool Search without catalog existence leaks."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from agent_platform.application.errors import Conflict
from agent_platform.domain.enums import ToolEffect
from agent_platform.tools.models import ToolDefinition


class SearchableTool(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=256)
    allowed_task_ids: frozenset[str] = Field(min_length=1)
    definition: ToolDefinition


class ToolSearchContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=256)
    task_id: str = Field(min_length=1, max_length=128)
    allowed_capabilities: frozenset[str]
    allowed_tool_names: frozenset[str]
    max_results: int = Field(default=8, ge=1, le=20)


class ToolSearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    definition: ToolDefinition
    score: int = Field(ge=1)
    matched_terms: tuple[str, ...]


class ToolSearchIndex:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str], SearchableTool] = {}

    def register(self, entry: SearchableTool) -> None:
        if entry.definition.effect is ToolEffect.COMMIT:
            raise ValueError("TOOL_SEARCH_COMMIT_FORBIDDEN: Commit tools never enter Agent search")
        key = (
            entry.tenant_id,
            entry.definition.name,
            entry.definition.version,
        )
        if key in self._entries:
            raise Conflict(
                "TOOL_SEARCH_ENTRY_EXISTS",
                "Tool Search entries are immutable",
                tenant_id=entry.tenant_id,
                tool_name=entry.definition.name,
                tool_version=entry.definition.version,
            )
        self._entries[key] = entry

    def search(
        self,
        query: str,
        context: ToolSearchContext,
    ) -> tuple[ToolSearchResult, ...]:
        if len(query) > 1_000:
            raise ValueError("TOOL_SEARCH_QUERY_TOO_LONG: query exceeds 1000 characters")
        terms = tuple(dict.fromkeys(re.findall(r"[a-z0-9]+", query.lower())))
        if not terms:
            return ()
        eligible: dict[str, SearchableTool] = {}
        for entry in self._entries.values():
            definition = entry.definition
            if entry.tenant_id not in {context.tenant_id, "*"}:
                continue
            if context.task_id not in entry.allowed_task_ids and "*" not in entry.allowed_task_ids:
                continue
            if definition.capability_name not in context.allowed_capabilities:
                continue
            if definition.name not in context.allowed_tool_names:
                continue
            if definition.effect is ToolEffect.COMMIT or not definition.enabled:
                continue
            current = eligible.get(definition.name)
            current_rank = (
                (
                    current.tenant_id == context.tenant_id,
                    tuple(int(part) for part in current.definition.version.split(".")),
                )
                if current
                else None
            )
            candidate_rank = (
                entry.tenant_id == context.tenant_id,
                tuple(int(part) for part in definition.version.split(".")),
            )
            if current_rank is None or candidate_rank > current_rank:
                eligible[definition.name] = entry

        results: list[ToolSearchResult] = []
        for entry in eligible.values():
            definition = entry.definition
            searchable = " ".join(
                (
                    definition.name,
                    definition.capability_name,
                    definition.description,
                )
            ).lower()
            matched = tuple(term for term in terms if term in searchable)
            if not matched:
                continue
            score = sum(3 if term in definition.name else 1 for term in matched)
            results.append(
                ToolSearchResult(
                    definition=definition,
                    score=score,
                    matched_terms=matched,
                )
            )
        results.sort(
            key=lambda result: (
                -result.score,
                result.definition.name,
            )
        )
        return tuple(results[: context.max_results])
