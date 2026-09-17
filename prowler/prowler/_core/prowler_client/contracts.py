"""Internal value types for synchronous Prowler invocation."""

from dataclasses import dataclass
from typing import Literal

from prowler._core.cli_engine.contracts import EnvironmentValue

from .ports import CredentialLeasePort

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


@dataclass(frozen=True)
class ProviderInvocation:
    """Provider-specific arguments, environment, and credential resources."""

    arguments: tuple[str, ...]
    environment: tuple[tuple[str, EnvironmentValue], ...]
    credential_leases: tuple[CredentialLeasePort, ...] = ()
