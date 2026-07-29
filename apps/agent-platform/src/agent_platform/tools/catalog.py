from __future__ import annotations

from agent_platform.domain.enums import RiskLevel, ToolEffect
from agent_platform.tools.adapters.reference import KnowledgeSearchAdapter, SandboxEmailAdapter
from agent_platform.tools.models import RegisteredTool, ToolDefinition
from agent_platform.tools.registry import ToolRegistry


def build_reference_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        RegisteredTool(
            ToolDefinition(
                name="knowledge.search",
                version="1.0.0",
                description="Search tenant-authorized, source-backed knowledge.",
                capability_name="knowledge.search",
                effect=ToolEffect.READ,
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "minLength": 1, "maxLength": 1_000},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 20},
                    },
                    "required": ["query", "limit"],
                    "additionalProperties": False,
                },
                output_schema={"type": "object"},
                risk=RiskLevel.MEDIUM,
                required_scopes=frozenset({"knowledge:read"}),
                supported_data_classes=frozenset({"public", "internal"}),
                allowed_network_targets=(),
                timeout_seconds=15,
                max_result_bytes=1_000_000,
                idempotency="none",
                approval_policy="none",
                adapter_ref="reference.knowledge",
            ),
            KnowledgeSearchAdapter(
                documents=[
                    {
                        "source_id": "market-sg-2026",
                        "title": "SG market overview",
                        "content": (
                            "SG has a mature digital economy, regional connectivity, "
                            "and a transparent regulatory environment."
                        ),
                        "uri": "https://example.test/sources/sg",
                    },
                    {
                        "source_id": "market-jp-2026",
                        "title": "JP market overview",
                        "content": (
                            "JP has a large enterprise market, strong incumbents, and "
                            "localization requirements."
                        ),
                        "uri": "https://example.test/sources/jp",
                    },
                    {
                        "source_id": "market-au-2026",
                        "title": "AU market overview",
                        "content": (
                            "AU has high digital adoption and a geographically dispersed "
                            "customer base."
                        ),
                        "uri": "https://example.test/sources/au",
                    },
                ]
            ),
        )
    )
    registry.register(
        RegisteredTool(
            ToolDefinition(
                name="email.prepare",
                version="1.0.0",
                description="Prepare a sandbox email preview; never sends from an Agent call.",
                capability_name="email.prepare",
                effect=ToolEffect.PREPARE,
                input_schema={
                    "type": "object",
                    "properties": {
                        "recipients": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 20,
                            "items": {"type": "string", "format": "email"},
                        },
                        "subject": {"type": "string", "minLength": 1, "maxLength": 200},
                        "body": {"type": "string", "minLength": 1, "maxLength": 100_000},
                        "artifact_ids": {
                            "type": "array",
                            "maxItems": 20,
                            "items": {"type": "string", "format": "uuid"},
                        },
                    },
                    "required": ["recipients", "subject", "body", "artifact_ids"],
                    "additionalProperties": False,
                },
                output_schema={"type": "object"},
                risk=RiskLevel.HIGH,
                required_scopes=frozenset({"email:prepare"}),
                commit_scopes=frozenset({"email:commit"}),
                supported_data_classes=frozenset({"internal"}),
                allowed_network_targets=(),
                timeout_seconds=15,
                max_result_bytes=100_000,
                idempotency="business_key",
                approval_policy="human",
                adapter_ref="reference.sandbox_email",
            ),
            SandboxEmailAdapter(allowed_domains={"example.test"}),
        )
    )
    return registry
