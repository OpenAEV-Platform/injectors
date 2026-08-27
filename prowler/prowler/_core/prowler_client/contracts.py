"""Internal ports and values for synchronous Prowler invocation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import SecretStr

from prowler._core.cli_engine import CommandResult, ValidatedCommandRequest
from prowler._core.cli_engine.contracts import EnvironmentValue


class CliEnginePort(Protocol):
    """Execute one validated command request."""

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        """Run the command synchronously."""


class CliEngineFactoryPort(Protocol):
    """Create CLI engines without executing them."""

    def create(self) -> CliEnginePort:
        """Create one engine."""


class CredentialFileFactoryPort(Protocol):
    """Materialize one secret in an owner-only temporary file."""

    def create(self, content: SecretStr) -> Path:
        """Return the path to a newly materialized secret."""


@dataclass(frozen=True)
class ProviderInvocation:
    """Provider-specific command arguments, environment, and temporary files."""

    arguments: tuple[str, ...]
    environment: tuple[tuple[str, EnvironmentValue], ...]
    temporary_files: tuple[Path, ...] = ()
