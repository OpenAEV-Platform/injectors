"""Distinct failure types for the generic CLI engine."""

from dataclasses import dataclass


class CliEngineError(Exception):
    """Base class for distinct generic CLI engine failures."""


class PolicyError(CliEngineError):
    """The policy boundary rejected the immutable specification."""


class ResolutionError(CliEngineError):
    """The resolution boundary could not resolve the specification."""


@dataclass(frozen=True)
class ExecutionError(CliEngineError):
    """Process failure retaining exact captured streams."""

    message: str
    stdout: bytes = b""
    stderr: bytes = b""
    return_code: int | None = None


@dataclass(frozen=True)
class ParsingError(CliEngineError):
    """Parser failure retaining the original process streams."""

    message: str
    stdout: bytes
    stderr: bytes
