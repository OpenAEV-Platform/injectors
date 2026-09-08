"""Internal ports and values for synchronous Prowler invocation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import SecretStr

from prowler._core.cli_engine import CommandResult, ValidatedCommandRequest
from prowler._core.cli_engine.contracts import EnvironmentValue

AwsServiceSelector = Literal["iam", "s3", "ec2"]
AzureServiceSelector = Literal["iam", "storage"]
GcpServiceSelector = Literal["iam", "compute"]
ServiceSelector = AwsServiceSelector | AzureServiceSelector | GcpServiceSelector
ComplianceSelector = Literal[
    "cis_3.0_aws",
    "cis_3.0_azure",
    "cis_3.0_gcp",
    "cis_1.12_kubernetes",
    "nis2_aws",
    "nis2_azure",
    "nis2_gcp",
    "iso27001_2022_aws",
    "iso27001_2022_azure",
    "iso27001_2022_gcp",
    "iso27001_2022_kubernetes",
    "mitre_attack_aws",
    "mitre_attack_azure",
    "mitre_attack_gcp",
]


class CliEnginePort(Protocol):
    """Execute one validated command request."""

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        """Run the command synchronously."""


class CliEngineFactoryPort(Protocol):
    """Create CLI engines without executing them."""

    def create(self) -> CliEnginePort:
        """Create one engine."""


class CredentialLeasePort(Protocol):
    """Own the lifecycle of one temporary credential resource."""

    @property
    def path(self) -> Path:
        """Return the temporary credential path."""

    def cleanup(self) -> None:
        """Idempotently remove the owned credential resources."""


class CredentialLeaseFactoryPort(Protocol):
    """Materialize one secret as a cross-platform temporary lease."""

    def create(self, content: SecretStr, *, suffix: str) -> CredentialLeasePort:
        """Return a newly materialized credential lease."""


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


@dataclass(frozen=True)
class ProviderInvocation:
    """Provider-specific arguments, environment, and credential resources."""

    arguments: tuple[str, ...]
    environment: tuple[tuple[str, EnvironmentValue], ...]
    credential_leases: tuple[CredentialLeasePort, ...] = ()
