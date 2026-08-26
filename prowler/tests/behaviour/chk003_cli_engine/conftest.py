"""Fixtures local to CHK.003 CLI engine behaviour."""

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class RecordingPorts:
    """Deterministic port bundle recording boundary order and values."""

    events: list[str] = field(default_factory=list)
    allowed: bool = True
    resolvable: bool = True
    outcome: Any = None
    parse_error: Exception | None = None
    invocation: Any = None
    parsed_payload: bytes | None = None

    def check(self, specification: Any) -> None:
        """Record policy evaluation and reject when configured."""
        self.events.append("policy")
        if not self.allowed:
            from prowler.cli_engine import PolicyError

            raise PolicyError("request rejected")

    def resolve(self, specification: Any) -> Any:
        """Record resolution and return the prepared specification."""
        self.events.append("resolution")
        if not self.resolvable:
            from prowler.cli_engine import ResolutionError

            raise ResolutionError("value unresolved")
        return specification

    def execute(self, specification: Any) -> Any:
        """Record execution and return the configured outcome."""
        self.events.append("execution")
        self.invocation = specification
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome

    def parse(self, parser: str, payload: bytes) -> object:
        """Record parsing and return deterministic parsed data."""
        self.events.append("parsing")
        self.parsed_payload = payload
        if self.parse_error is not None:
            raise self.parse_error
        return {"parser": parser, "size": len(payload)}


@pytest.fixture
def recording_ports() -> RecordingPorts:
    """Return fresh deterministic CLI boundary ports."""
    return RecordingPorts()
