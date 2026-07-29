from __future__ import annotations

from agent_platform.application.errors import Conflict, PlatformError
from agent_platform.domain.enums import ToolEffect
from agent_platform.tools.models import RegisteredTool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[tuple[str, str], RegisteredTool] = {}
        self._agent_visible: set[tuple[str, str]] = set()

    def register(self, tool: RegisteredTool, *, expose_to_agent: bool = True) -> None:
        key = (tool.definition.name, tool.definition.version)
        if key in self._tools:
            raise Conflict(
                "TOOL_VERSION_ALREADY_REGISTERED",
                "Tool name and version are immutable",
                tool_name=key[0],
                tool_version=key[1],
            )
        if expose_to_agent and tool.definition.effect == ToolEffect.COMMIT:
            raise ValueError("COMMIT_TOOL_NOT_AGENT_VISIBLE")
        self._tools[key] = tool
        if expose_to_agent:
            self._agent_visible.add(key)

    async def resolve(self, name: str, tenant_id: str) -> RegisteredTool:
        candidates = [
            tool
            for (tool_name, _), tool in self._tools.items()
            if tool_name == name and tool.definition.enabled
        ]
        if not candidates:
            raise PlatformError(
                "TOOL_NOT_FOUND",
                f"TOOL_NOT_FOUND: tool {name!r} is not registered or enabled",
                http_status=404,
                context={"tool_name": name, "tenant_id": tenant_id},
            )
        candidates.sort(key=lambda item: item.definition.version, reverse=True)
        return candidates[0]

    async def resolve_exact(self, name: str, version: str, tenant_id: str) -> RegisteredTool:
        tool = self._tools.get((name, version))
        if tool is None or not tool.definition.enabled:
            raise PlatformError(
                "TOOL_NOT_FOUND",
                (f"TOOL_NOT_FOUND: tool {name!r} version {version!r} is not registered or enabled"),
                http_status=404,
                context={
                    "tool_name": name,
                    "tool_version": version,
                    "tenant_id": tenant_id,
                },
            )
        return tool

    async def resolve_for_agent(
        self, names: list[str] | tuple[str, ...], tenant_id: str
    ) -> tuple[RegisteredTool, ...]:
        resolved: list[RegisteredTool] = []
        for name in names:
            tool = await self.resolve(name, tenant_id)
            key = (tool.definition.name, tool.definition.version)
            if key not in self._agent_visible or tool.definition.effect == ToolEffect.COMMIT:
                raise PlatformError(
                    "TOOL_NOT_AGENT_VISIBLE",
                    f"TOOL_NOT_AGENT_VISIBLE: tool {name!r} is not exposed to agents",
                    http_status=404,
                    context={"tool_name": name, "tenant_id": tenant_id},
                )
            resolved.append(tool)
        return tuple(resolved)

    def definitions(self) -> tuple[object, ...]:
        return tuple(tool.definition for tool in self._tools.values())
