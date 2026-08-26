"""Fixtures local to CHK.003 behaviour tests."""

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass
class RecordingPorts:
    """Deterministic ports recording identity, order, and exact payloads."""

    events: list[str] = field(default_factory=list)
    seen: list[Any] = field(default_factory=list)
    policy_error: Any = None
    resolution_error: Any = None
    execution_result: Any = None
    parsing_result: Any = None

    def check(self, specification: Any) -> Any:
        self.events.append("policy")
        self.seen.append(specification)
        return self.policy_error

    def validate(self, specification: Any) -> Any:
        self.events.append("resolution")
        self.seen.append(specification)
        return self.resolution_error

    def execute(self, specification: Any) -> Any:
        self.events.append("execution")
        self.seen.append(specification)
        return self.execution_result

    def parse(self, specification: Any, payload: bytes) -> Any:
        self.events.append("parsing")
        self.seen.append(specification)
        if self.parsing_result is not None:
            return self.parsing_result
        return {"parser": specification.output.parser, "bytes": payload}


@pytest.fixture
def recording_ports() -> RecordingPorts:
    return RecordingPorts()
