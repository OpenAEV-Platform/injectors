"""Immutable contracts for structured local process execution."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import SecretStr

EnvironmentValue = str | SecretStr


@dataclass(frozen=True)
class OutputSpecification:
    """Select one parser and its optional regular expression."""

    parser: str = "raw"
    pattern: str | None = None


@dataclass(frozen=True)
class ValidatedCommandRequest:
    """Validated caller input copied into an execution specification."""

    executable: str
    arguments: Sequence[str]
    environment: Mapping[str, EnvironmentValue] | Sequence[tuple[str, EnvironmentValue]]
    working_directory: str | None
    input_bytes: bytes
    output: OutputSpecification
    timeout_seconds: float
    maximum_accepted_output_bytes: int


@dataclass(frozen=True)
class ExecutionSpecification:
    """Deeply immutable policy and execution unit."""

    executable: str
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, EnvironmentValue], ...]
    working_directory: str | None
    input_bytes: bytes
    output: OutputSpecification
    timeout_seconds: float
    maximum_accepted_output_bytes: int

    @classmethod
    def from_request(cls, request: ValidatedCommandRequest) -> "ExecutionSpecification":
        """Defensively copy nested request values."""
        environment = (
            tuple(request.environment.items())
            if isinstance(request.environment, Mapping)
            else tuple(request.environment)
        )
        return cls(
            executable=request.executable,
            arguments=tuple(request.arguments),
            environment=environment,
            working_directory=request.working_directory,
            input_bytes=request.input_bytes,
            output=request.output,
            timeout_seconds=request.timeout_seconds,
            maximum_accepted_output_bytes=request.maximum_accepted_output_bytes,
        )

    @property
    def argv(self) -> tuple[str, ...]:
        """Return structured argv without shell interpolation."""
        return (self.executable, *self.arguments)


@dataclass(frozen=True)
class ProcessOutcome:
    """Raw process completion values."""

    return_code: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class CommandResult:
    """Result envelope for success and expected failures."""

    specification: ExecutionSpecification
    stdout: bytes = b""
    stderr: bytes = b""
    return_code: int | None = None
    parsed: Any | None = None
    error: Any | None = None
