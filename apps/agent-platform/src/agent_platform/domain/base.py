"""Shared Pydantic configuration and value helpers for the domain layer."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict

JsonValue = Any


def normalize_utc_datetime(value: datetime) -> datetime:
    """Reject ambiguous wall-clock values and normalize instants to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("TIMEZONE_REQUIRED: datetime must include an explicit UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(normalize_utc_datetime)]


class StrictDomainModel(BaseModel):
    """Fail closed on unknown input and make authoritative values immutable."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )
