from __future__ import annotations

import json

import pytest

from agent_platform.agents.context_builder import (
    ContextAssemblyError,
    ContextBlock,
    ContextBuilder,
)


def block(
    source_id: str,
    content: object,
    *,
    content_hash: str,
    trust: str = "untrusted/data",
    allowed_use: str = "evidence_only",
    required: bool = False,
) -> ContextBlock:
    return ContextBlock.model_validate(
        {
            "source_id": source_id,
            "source_time": "2026-07-24T00:00:00Z",
            "source_version": "v7",
            "classification": "internal",
            "owner": "owner",
            "content_hash": content_hash,
            "trust": trust,
            "allowed_use": allowed_use,
            "required": required,
            "content": content,
        }
    )


def test_budget_uses_whole_blocks_and_reports_exact_provider_neutral_upper_bound() -> None:
    required = block(
        "contract",
        "goal and must success criteria",
        content_hash="a" * 64,
        trust="trusted/immutable",
        allowed_use="task_contract",
        required=True,
    )
    optional = block(
        "large-evidence",
        "证据" * 500,
        content_hash="b" * 64,
    )
    probe_builder = ContextBuilder(max_bytes=100_000, max_tokens=100_000)
    probe = probe_builder.assemble(
        [required],
        allowed_uses=frozenset({"task_contract", "evidence_only"}),
        required_uses=frozenset({"task_contract"}),
    )
    exact_required_bytes = probe.manifest["budget"]["used_bytes"]

    builder = ContextBuilder(
        max_bytes=exact_required_bytes + 8,
        max_tokens=100_000,
    )
    assembled = builder.assemble(
        [optional, required],
        allowed_uses=frozenset({"task_contract", "evidence_only"}),
        required_uses=frozenset({"task_contract"}),
    )

    assert [item["source_id"] for item in assembled] == ["contract"]
    assert assembled[0]["content"] == "goal and must success criteria"
    assert assembled.manifest["truncated"] is True
    assert assembled.manifest["complete"] is False
    assert assembled.manifest["omitted_sources"] == [
        {
            "source_id": "large-evidence",
            "source_version": "v7",
            "content_hash": "b" * 64,
            "reason": "budget_exceeded",
        }
    ]
    model_input = builder.as_model_input(assembled)
    assert len(model_input.encode("utf-8")) == assembled.manifest["budget"]["used_bytes"]
    assert assembled.manifest["budget"]["used_tokens"] == assembled.manifest["budget"]["used_bytes"]
    assert assembled.manifest["budget"]["counter"] == "utf8-byte-upper-bound"
    assert assembled.manifest["budget"]["counter_version"] == "1.0"
    assert assembled.manifest["budget"]["estimated_upper_bound"] is True
    assert "证据" not in model_input


def test_allowlist_stable_deduplication_and_recursive_redaction_are_manifested() -> None:
    sensitive = {
        "safe": "visible",
        "nested": {
            "api_token": "do-not-expose",
            "items": [{"password": "hidden"}, {"note": "keep"}],
        },
    }
    blocks = [
        block("first", sensitive, content_hash="c" * 64),
        block("duplicate", sensitive, content_hash="c" * 64),
        block(
            "not-allowlisted",
            "must not reach the model",
            content_hash="d" * 64,
            allowed_use="tool_description",
        ),
    ]
    builder = ContextBuilder(max_bytes=10_000, max_tokens=10_000)

    assembled = builder.assemble(
        blocks,
        allowed_uses=frozenset({"evidence_only"}),
    )

    assert [item["source_id"] for item in assembled] == ["first"]
    assert assembled[0]["channel"] == "untrusted_data"
    assert assembled[0]["can_instruct"] is False
    assert assembled[0]["content"] == {
        "safe": "visible",
        "nested": {
            "api_token": "[REDACTED]",
            "items": [{"password": "[REDACTED]"}, {"note": "keep"}],
        },
    }
    source = assembled.manifest["sources"][0]
    assert source["source_version"] == "v7"
    assert source["redacted_paths"] == [
        "$.nested.api_token",
        "$.nested.items[0].password",
    ]
    assert source["rendered_hash"] != source["content_hash"]
    assert [
        (item["source_id"], item["reason"]) for item in assembled.manifest["omitted_sources"]
    ] == [
        ("duplicate", "duplicate_content"),
        ("not-allowlisted", "use_not_allowed"),
    ]
    serialized = json.loads(builder.as_model_input(assembled))
    assert serialized["security_notice"]
    assert serialized["context"] == list(assembled)
    assert "do-not-expose" not in builder.as_model_input(assembled)


def test_required_context_missing_or_over_budget_fails_closed() -> None:
    builder = ContextBuilder(max_bytes=256, max_tokens=256)

    with pytest.raises(ContextAssemblyError, match="CONTEXT_REQUIRED_USE_MISSING"):
        builder.assemble(
            [],
            allowed_uses=frozenset({"task_contract"}),
            required_uses=frozenset({"task_contract"}),
        )

    oversized = block(
        "contract",
        "x" * 1_000,
        content_hash="e" * 64,
        trust="trusted/immutable",
        allowed_use="task_contract",
        required=True,
    )
    with pytest.raises(ContextAssemblyError, match="CONTEXT_REQUIRED_BLOCK_OVER_BUDGET"):
        builder.assemble(
            [oversized],
            allowed_uses=frozenset({"task_contract"}),
            required_uses=frozenset({"task_contract"}),
        )
