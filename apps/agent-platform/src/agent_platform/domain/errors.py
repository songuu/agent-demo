"""Stable, contextual errors emitted by deterministic domain controls."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class DomainInvariantError(ValueError):
    """An input is well formed but violates an authoritative business invariant."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.context = dict(context or {})
        super().__init__(self.__str__())

    def __str__(self) -> str:
        suffix = ""
        if self.context:
            rendered = ", ".join(
                f"{key}={self.context[key]!r}" for key in sorted(self.context)
            )
            suffix = f" ({rendered})"
        return f"{self.code}: {self.message}{suffix}"


class DomainTransitionError(DomainInvariantError):
    """A state transition was attempted outside the explicit state machine."""
