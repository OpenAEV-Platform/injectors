"""Internal dependency ports for synchronous Prowler invocation."""

from pathlib import Path
from typing import Protocol

from pydantic import SecretStr
from pyoaev.credential import MaterializedCredential, ResolvedSecret

from prowler._core.cli_engine import CommandResult, ValidatedCommandRequest


class CliEnginePort(Protocol):
    """Execute one validated command request."""

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        """Run the command synchronously."""


class CliEngineFactoryPort(Protocol):
    """Create CLI engines without executing them."""

    def create(self) -> CliEnginePort:
        """Create one engine."""


class CredentialResourcePort(Protocol):
    """Own the lifecycle of temporary credential resources."""

    def cleanup(self) -> None:
        """Idempotently remove the owned credential resources."""


class CredentialLeasePort(CredentialResourcePort, Protocol):
    """Own the lifecycle of one temporary credential file."""

    @property
    def path(self) -> Path:
        """Return the temporary credential path."""


class MaterializedCredentialLeasePort(CredentialResourcePort, Protocol):
    """Own the environment and files materialized from a resolved secret."""

    @property
    def credential(self) -> MaterializedCredential:
        """Return the materialized environment, files, and secret type."""


class CredentialLeaseFactoryPort(Protocol):
    """Materialize one secret as a cross-platform temporary lease."""

    def create(self, content: SecretStr, *, suffix: str) -> CredentialLeasePort:
        """Return a newly materialized credential lease."""

    def materialize(
        self, resolved_secret: ResolvedSecret
    ) -> MaterializedCredentialLeasePort:
        """Return the materialized credential of one resolved secret."""


class OutputWorkspacePort(Protocol):
    """Own one controlled Prowler output directory and artifact."""

    @property
    def directory(self) -> Path:
        """Return the workspace directory supplied to Prowler."""

    @property
    def backend(self) -> str:
        """Return the closed storage-backend label."""

    def read_artifact(self, *, maximum_bytes: int) -> bytes:
        """Securely read the exact bounded output artifact."""

    def cleanup(self) -> None:
        """Idempotently remove the recursively owned workspace."""


class OutputWorkspaceFactoryPort(Protocol):
    """Create controlled Prowler output workspaces without executing Prowler."""

    def create(self) -> OutputWorkspacePort:
        """Return one unique output workspace."""
