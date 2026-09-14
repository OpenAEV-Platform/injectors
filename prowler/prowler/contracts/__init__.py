"""Prowler contract declarations and the executable default registry."""

from .aws import (
    AwsBaseContract,
    AwsEc2Contract,
    AwsIamContract,
    AwsS3Contract,
    AwsServiceContract,
)
from .azure import (
    AzureBaseContract,
    AzureIamContract,
    AzureServiceContract,
    AzureStorageContract,
)
from .base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    ProviderName,
    RouteFamily,
)
from .catalog import ROUTE_CATALOG, RouteDescriptor
from .cis import (
    AwsCisContract,
    AzureCisContract,
    CisComplianceContract,
    GcpCisContract,
    KubernetesCisContract,
)
from .dispatcher import ContractDispatcher, RouteHandler, RouteNotFoundError
from .gcp import GcpBaseContract, GcpComputeContract, GcpIamContract, GcpServiceContract
from .kubernetes import KubernetesBaseContract
from .mitre import (
    AwsMitreContract,
    AzureMitreContract,
    GcpMitreContract,
    MitreComplianceContract,
)
from .nis2_iso27001 import (
    AwsIso27001Contract,
    AwsNis2Contract,
    AzureIso27001Contract,
    AzureNis2Contract,
    GcpIso27001Contract,
    GcpNis2Contract,
    Iso27001ComplianceContract,
    KubernetesIso27001Contract,
    Nis2ComplianceContract,
)
from .registry import (
    DEFAULT_PROWLER_CONTRACTS,
    PROWLER_CONTRACT_NAMESPACE,
    ProwlerContracts,
    stable_contract_id,
)
from .selectable import (
    AwsSelectComplianceContract,
    AwsSelectServiceContract,
    AzureSelectComplianceContract,
    AzureSelectServiceContract,
    GcpSelectComplianceContract,
    GcpSelectServiceContract,
)

__all__ = [
    "BaseProwlerContract",
    "AwsBaseContract",
    "AwsEc2Contract",
    "AwsIamContract",
    "AwsS3Contract",
    "AwsServiceContract",
    "AzureBaseContract",
    "AzureIamContract",
    "AzureServiceContract",
    "AzureStorageContract",
    "AwsCisContract",
    "AwsIso27001Contract",
    "AwsNis2Contract",
    "AwsMitreContract",
    "AzureCisContract",
    "AzureIso27001Contract",
    "AzureNis2Contract",
    "AzureMitreContract",
    "CisComplianceContract",
    "GcpBaseContract",
    "GcpComputeContract",
    "GcpIamContract",
    "GcpServiceContract",
    "GcpCisContract",
    "GcpIso27001Contract",
    "GcpNis2Contract",
    "GcpMitreContract",
    "Iso27001ComplianceContract",
    "KubernetesBaseContract",
    "KubernetesCisContract",
    "KubernetesIso27001Contract",
    "Nis2ComplianceContract",
    "MitreComplianceContract",
    "AwsSelectServiceContract",
    "AwsSelectComplianceContract",
    "AzureSelectServiceContract",
    "AzureSelectComplianceContract",
    "GcpSelectServiceContract",
    "GcpSelectComplianceContract",
    "ContractDispatcher",
    "ContractExecutionOutcome",
    "ContractInputError",
    "ContractInputIssue",
    "DEFAULT_PROWLER_CONTRACTS",
    "PROWLER_CONTRACT_NAMESPACE",
    "ProviderName",
    "ProwlerContracts",
    "ROUTE_CATALOG",
    "RouteDescriptor",
    "RouteFamily",
    "RouteHandler",
    "RouteNotFoundError",
    "stable_contract_id",
]
