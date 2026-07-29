from __future__ import annotations

from typing import Any, cast

from sqlalchemy import any_, literal, select
from sqlalchemy.dialects import postgresql

from agent_platform.infrastructure.persistence.models import WebhookEndpoint


def test_webhook_event_type_membership_compiles_to_postgres_any() -> None:
    statement = select(WebhookEndpoint.endpoint_id).where(
        literal("run.completed") == any_(WebhookEndpoint.event_types)
    )

    rendered = str(
        statement.compile(
            dialect=cast(Any, postgresql.dialect)(),
            compile_kwargs={"literal_binds": True},
        )
    )

    assert "'run.completed' = ANY (webhook_endpoints.event_types)" in rendered
