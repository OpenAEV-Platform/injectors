"""Internal value types for synchronous Prowler invocation."""

from dataclasses import dataclass
from typing import Literal

from prowler._core.cli_engine.contracts import EnvironmentValue

from .ports import CredentialLeasePort

AwsServiceSelector = Literal["iam", "s3", "ec2"]


@dataclass(frozen=True)
class ProviderInvocation:
    """Provider-specific arguments, environment, and credential resources."""

    arguments: tuple[str, ...]
    environment: tuple[tuple[str, EnvironmentValue], ...]
    credential_leases: tuple[CredentialLeasePort, ...] = ()
