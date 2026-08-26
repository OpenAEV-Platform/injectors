"""Generic hexagonal engine for structured local process execution."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from prowler import cli_engine_errors as errors

ExecutionError = errors.ExecutionError
ParsingError = errors.ParsingError
PolicyError = errors.PolicyError
ResolutionError = errors.ResolutionError


def _freeze_environment(
    environment: Mapping[str, str] | Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    """Copy environment entries into a stable ordered tuple."""
    if isinstance(environment, Mapping):
        return tuple(environment.items())
    return tuple(environment)


@dataclass(frozen=True)
class ValidatedCliRequest:
    """Validated command inputs used to derive an execution specification."""

    executable: str
    arguments: Sequence[str]
    environment: Mapping[str, str] | Sequence[tuple[str, str]]
    working_directory: str | None
    input_bytes: bytes
    parser: str


@dataclass(frozen=True)
class ExecutionSpecification:
    """Deeply immutable structured process and parser specification."""

    executable: str
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    working_directory: str | None
    input_bytes: bytes
    parser: str

    @classmethod
    def from_request(cls, request: ValidatedCliRequest) -> ExecutionSpecification:
        """Copy a validated request into immutable nested values."""
        return cls(
            executable=request.executable,
            arguments=tuple(request.arguments),
            environment=_freeze_environment(request.environment),
            working_directory=request.working_directory,
            input_bytes=request.input_bytes,
            parser=request.parser,
        )

    @property
    def argv(self) -> tuple[str, ...]:
        """Return executable and ordered arguments as structured values."""
        return (self.executable, *self.arguments)


@dataclass(frozen=True)
class ProcessOutcome:
    """Exact process outcome returned by an executor port."""

    return_code: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class ExecutionSuccess:
    """Parsed result accompanied by exact captured process streams."""

    parsed: object
    stdout: bytes
    stderr: bytes


class PolicyPort(Protocol):
    """Authorize one immutable execution specification."""

    def check(self, specification: ExecutionSpecification) -> None:
        """Raise PolicyError when execution is not permitted."""


class ResolverPort(Protocol):
    """Resolve values needed by one immutable execution specification."""

    def resolve(self, specification: ExecutionSpecification) -> None:
        """Resolve required values or raise ResolutionError."""


class ExecutorPort(Protocol):
    """Execute one immutable specification without shell interpretation."""

    def execute(self, specification: ExecutionSpecification) -> ProcessOutcome:
        """Return exact process bytes and return code."""


class ParserPort(Protocol):
    """Parse exact successful stdout bytes."""

    def parse(self, parser: str, payload: bytes) -> object:
        """Return the selected parser's result."""


class CliEngine:
    """Orchestrate policy, resolution, execution, and parsing in order."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        resolver: ResolverPort,
        executor: ExecutorPort,
        parser: ParserPort,
    ) -> None:
        """Bind injected ports without selecting provider-specific behavior."""
        self._policy = policy
        self._resolver = resolver
        self._executor = executor
        self._parser = parser

    def run(self, request: ValidatedCliRequest) -> ExecutionSuccess:
        """Run a validated request through each boundary exactly in order."""
        specification = ExecutionSpecification.from_request(request)
        self._policy.check(specification)
        self._resolver.resolve(specification)
        try:
            outcome = self._executor.execute(specification)
        except ExecutionError:
            raise
        except OSError as error:
            raise ExecutionError(str(error)) from error
        if outcome.return_code != 0:
            raise ExecutionError(
                "process returned an unsuccessful outcome",
                stdout=outcome.stdout,
                stderr=outcome.stderr,
                return_code=outcome.return_code,
            )
        try:
            parsed = self._parser.parse(specification.parser, outcome.stdout)
        except Exception as error:
            message = error.message if isinstance(error, ParsingError) else str(error)
            raise ParsingError(
                message, stdout=outcome.stdout, stderr=outcome.stderr
            ) from error
        return ExecutionSuccess(parsed, outcome.stdout, outcome.stderr)


class SubprocessExecutor:
    """Subprocess-backed executor using structured argv and shell=False."""

    def execute(self, specification: ExecutionSpecification) -> ProcessOutcome:
        """Execute a specification and preserve all process bytes exactly."""
        completed = subprocess.run(  # noqa: S603 - policy-approved structured argv
            specification.argv,
            input=specification.input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=specification.working_directory,
            env=dict(specification.environment),
            shell=False,
            check=False,
        )
        return ProcessOutcome(completed.returncode, completed.stdout, completed.stderr)
