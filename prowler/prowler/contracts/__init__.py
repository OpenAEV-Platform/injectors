"""Prowler contract declarations and the executable default registry."""

from .aws import AwsBaseContract
from .azure import AzureBaseContract
from .base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    ProviderName,
    RouteFamily,
)
from .catalog import ROUTE_CATALOG, RouteDescriptor
from .dispatcher import ContractDispatcher, RouteHandler, RouteNotFoundError
from .gcp import GcpBaseContract
from .kubernetes import KubernetesBaseContract
from .registry import (
    DEFAULT_PROWLER_CONTRACTS,
    PROWLER_CONTRACT_NAMESPACE,
    ProwlerContracts,
    stable_contract_id,
)

__all__ = [
    "BaseProwlerContract",
    "AwsBaseContract",
    "AzureBaseContract",
    "GcpBaseContract",
    "KubernetesBaseContract",
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
