from __future__ import annotations

from collections.abc import Mapping
from functools import partial
from typing import TextIO

import structlog
from opentelemetry import trace
from structlog.typing import EventDict, Processor

SECRET_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "api_key",
        "openai_api_key",
        "password",
        "secret",
        "token",
        "credential",
    }
)
CONTENT_KEYS = frozenset(
    {
        "args",
        "arguments",
        "body",
        "canonical_payload",
        "comment",
        "content",
        "goal",
        "input",
        "instructions",
        "messages",
        "model_input",
        "model_output",
        "output",
        "parameters",
        "preview",
        "prompt",
        "query",
        "raw_content",
        "result",
        "tool_result",
    }
)


def _redact(value: object, key: str = "") -> object:
    lowered = key.lower()
    if any(secret in lowered for secret in SECRET_KEYS):
        return "[REDACTED]"
    if lowered in CONTENT_KEYS:
        return "[CONTENT_OMITTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    return value


def redact_event(
    logger: object,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    del logger, method_name
    redacted: EventDict = {}
    for key, value in event_dict.items():
        redacted[key] = _redact(value, key)
    return redacted


def add_schema_fields(
    logger: object,
    method_name: str,
    event_dict: EventDict,
    *,
    service_name: str,
) -> EventDict:
    del logger, method_name
    event_dict.setdefault("log_schema_version", "1.0")
    event_dict.setdefault("service", service_name)
    return event_dict


def add_trace_fields(
    logger: object,
    method_name: str,
    event_dict: EventDict,
) -> EventDict:
    del logger, method_name
    span_context = trace.get_current_span().get_span_context()
    if span_context.is_valid:
        event_dict.setdefault("trace_id", f"{span_context.trace_id:032x}")
        event_dict.setdefault("span_id", f"{span_context.span_id:016x}")
    return event_dict


def configure_logging(
    *,
    json_logs: bool = True,
    stream: TextIO | None = None,
    cache_logger: bool = True,
    service_name: str = "agent-platform",
) -> None:
    renderer: Processor
    if json_logs:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        partial(add_schema_fields, service_name=service_name),
        add_trace_fields,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_event,
        renderer,
    ]
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=stream),
        cache_logger_on_first_use=cache_logger,
    )
