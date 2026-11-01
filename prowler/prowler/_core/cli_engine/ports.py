"""Hexagonal ports for CLI-engine boundaries."""

from typing import Any, Protocol

from .contracts import ExecutionSpecification, ProcessOutcome
from .errors import ExecutionError, ParsingError, PolicyError, ResolutionError


class PolicyPort(Protocol):
    """Authorize an exact specification."""

    def check(self, specification: ExecutionSpecification) -> PolicyError | None: ...


class BinaryResolverPort(Protocol):
    """Validate availability without replacing the executable."""

    def validate(
        self, specification: ExecutionSpecification
    ) -> ResolutionError | None: ...


class ExecutorPort(Protocol):
    """Execute structured argv."""

    def execute(
        self, specification: ExecutionSpecification
    ) -> ProcessOutcome | ExecutionError: ...


class OutputParserPort(Protocol):
    """Parse stdout under the exact specification."""

    def parse(
        self, specification: ExecutionSpecification, payload: bytes
    ) -> Any | ParsingError: ...
