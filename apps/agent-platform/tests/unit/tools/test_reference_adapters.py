from __future__ import annotations

import pytest

from agent_platform.tools.adapters.reference import (
    KnowledgeSearchAdapter,
    SandboxEmailAdapter,
)


@pytest.mark.asyncio
async def test_knowledge_search_is_bounded_and_source_backed() -> None:
    adapter = KnowledgeSearchAdapter(
        documents=[
            {
                "source_id": "source-sg",
                "title": "Singapore market",
                "content": "Singapore has a mature digital economy.",
                "uri": "https://example.test/sg",
            },
            {
                "source_id": "source-jp",
                "title": "Japan market",
                "content": "Japan has a large enterprise market.",
                "uri": "https://example.test/jp",
            },
        ]
    )
    result = await adapter.read({"query": "Singapore", "limit": 1}, object())
    assert result["row_count"] == 1
    assert result["items"][0]["source_id"] == "source-sg"
    assert "captured_at" in result["items"][0]


@pytest.mark.asyncio
async def test_sandbox_email_commit_is_idempotent_and_verifiable() -> None:
    adapter = SandboxEmailAdapter(allowed_domains={"example.test"})
    payload = {
        "recipients": ["leader@example.test"],
        "subject": "Report",
        "body": "Source-backed summary",
        "artifact_ids": [],
    }
    preview = await adapter.preview(payload, object())
    first = await adapter.commit(payload, object(), "business-1")
    second = await adapter.commit(payload, object(), "business-1")
    verification = await adapter.verify(object(), first, object())

    assert preview["side_effect"] == "none_until_commit"
    assert first == second
    assert adapter.commit_count == 1
    assert verification["passed"] is True


@pytest.mark.asyncio
async def test_sandbox_email_rejects_unapproved_recipient_domain() -> None:
    adapter = SandboxEmailAdapter(allowed_domains={"example.test"})
    with pytest.raises(ValueError, match="RECIPIENT_DOMAIN_DENIED"):
        await adapter.preview(
            {
                "recipients": ["external@evil.test"],
                "subject": "No",
                "body": "No",
                "artifact_ids": [],
            },
            object(),
        )
