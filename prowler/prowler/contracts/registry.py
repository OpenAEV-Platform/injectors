"""Explicit registry and stable identity strategy for concrete contracts."""

import inspect
from collections.abc import Iterable
from typing import cast
from uuid import UUID, uuid5

from pyoaev.contracts.contract_config import prepare_contracts

from .aws import AwsBaseContract, AwsEc2Contract, AwsIamContract, AwsS3Contract
from .azure import AzureBaseContract, AzureIamContract, AzureStorageContract
from .base import BaseProwlerContract
from .catalog import ROUTE_CATALOG
from .cis import AwsCisContract, AzureCisContract, GcpCisContract, KubernetesCisContract
from .gcp import GcpBaseContract, GcpComputeContract, GcpIamContract
from .kubernetes import KubernetesBaseContract

# Committed project namespace: changing it would break stable platform identities.
PROWLER_CONTRACT_NAMESPACE = UUID("ee49522d-80b9-5d71-b164-569ee61a75bd")


def stable_contract_id(route_name: str) -> UUID:
    """Derive a stable UUIDv5 from the exact canonical route name."""
    return uuid5(PROWLER_CONTRACT_NAMESPACE, route_name)


class ProwlerContracts:
    """Validate, instantiate, resolve, and serialize concrete route contracts."""

    def __init__(
        self, contract_classes: Iterable[type[BaseProwlerContract]] = ()
    ) -> None:
        """Build an isolated registry from explicitly supplied classes."""
        self._by_id: dict[str, BaseProwlerContract] = {}
        self._routes: set[str] = set()
        catalog = {route.route_name: route for route in ROUTE_CATALOG}
        for contract_class in contract_classes:
            if not inspect.isclass(contract_class) or not issubclass(
                contract_class, BaseProwlerContract
            ):
                raise ValueError("registry entries must be Prowler contract classes")
            if inspect.isabstract(contract_class):
                raise ValueError("abstract Prowler contracts cannot be registered")
            instance = contract_class()
            route = catalog.get(instance.route_name)
            if route is None:
                raise ValueError("registered route is not canonical")
            if route.provider != instance.provider or route.family != instance.family:
                raise ValueError(
                    "registered route metadata does not agree with catalog"
                )
            expected_id = str(stable_contract_id(instance.route_name))
            if instance.contract_id != expected_id:
                raise ValueError("registered contract ID is not the stable route UUID")
            if instance.external_id != f"prowler:{instance.route_name}":
                raise ValueError(
                    "registered external ID is not the stable route identity"
                )
            if expected_id in self._by_id or instance.route_name in self._routes:
                raise ValueError("duplicate Prowler contract ID or route")
            self._by_id[expected_id] = instance
            self._routes.add(instance.route_name)

    def resolve(self, contract_id: str) -> BaseProwlerContract:
        """Resolve an exact registered platform identifier."""
        try:
            return self._by_id[contract_id]
        except KeyError:
            raise LookupError("selected Prowler contract is not registered") from None

    def __len__(self) -> int:
        """Return the number of registered concrete contracts."""
        return len(self._by_id)

    def contracts(self) -> list[dict[str, object]]:
        """Prepare only explicitly registered concrete contracts for configuration."""
        return cast(
            list[dict[str, object]],
            prepare_contracts(
                [contract.build_contract() for contract in self._by_id.values()]
            ),
        )


DEFAULT_PROWLER_CONTRACTS = ProwlerContracts(
    (
        AwsBaseContract,
        AzureBaseContract,
        GcpBaseContract,
        KubernetesBaseContract,
        AwsIamContract,
        AwsS3Contract,
        AwsEc2Contract,
        AzureIamContract,
        AzureStorageContract,
        GcpIamContract,
        GcpComputeContract,
        AwsCisContract,
        AzureCisContract,
        GcpCisContract,
        KubernetesCisContract,
    )
)
