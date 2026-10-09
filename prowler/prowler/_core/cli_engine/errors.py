"""Distinct expected CLI-engine failures carried by CommandResult."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CliEngineError:
    """Base data contract for expected failures."""

    message: str
    kind: str = "cli_engine_error"


@dataclass(frozen=True)
class PolicyError(CliEngineError):
    """Policy rejected the exact immutable specification."""

    kind: str = "policy_rejected"


@dataclass(frozen=True)
class ResolutionError(CliEngineError):
    """The exact executable could not be validated."""

    kind: str = "resolution_failed"


@dataclass(frozen=True)
class ExecutionError(CliEngineError):
    """Process startup or completion failed with exact available bytes."""

    kind: str = "execution_failed"
    stdout: bytes = b""
    stderr: bytes = b""
    return_code: int | None = None
    cause: str | None = None


@dataclass(frozen=True)
class ParsingError(CliEngineError):
    """Parsing failed; engine-owned fields carry process evidence."""

    kind: str = "parsing_failed"
    stdout: bytes = b""
    stderr: bytes = b""
    context: tuple[tuple[str, str], ...] = ()
    cause: str | None = None
