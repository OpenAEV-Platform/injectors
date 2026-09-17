"""Executable complete-scope and service-specific Azure contracts."""

from typing import ClassVar, get_args

from prowler._core.prowler_client import AzureServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AzureProviderInput, ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome, RouteFamily
from .compliance import FixedServiceContract


class AzureBaseContract(BaseProwlerContract):
    """Run the complete Azure provider scope and retain mapped Azure findings."""

    contract_id: ClassVar[str] = "00558d49-06ee-5a6f-80e6-4dae205be992"
    external_id: ClassVar[str] = "prowler:azure"
    route_name: ClassVar[str] = "azure"
    provider = "azure"
    family: ClassVar[RouteFamily] = "base"
    label = "Prowler Azure"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered Azure findings only."""
        return self._execute_scoped(config, provider)


class AzureServiceContract(FixedServiceContract):
    """Execute one route-owned Azure service selector through the CHK.004 seam."""

    provider = "azure"
    service_selector: ClassVar[AzureServiceSelector]
    service_selectors = get_args(AzureServiceSelector)
    provider_input_type = AzureProviderInput
    provider_label = "Azure"
    provider_article = "an"


class AzureIamContract(AzureServiceContract):
    """Run only Prowler Azure IAM checks."""

    contract_id = "b559fad9-b928-5bfb-bf31-10479e0bf8c1"
    external_id = "prowler:azure/iam"
    route_name = "azure/iam"
    label = "Prowler Azure IAM"
    service_selector = "iam"


class AzureStorageContract(AzureServiceContract):
    """Run only Prowler Azure Storage checks."""

    contract_id = "f056c4d2-6ee8-5554-8f23-b67cf0ff4e58"
    external_id = "prowler:azure/storage"
    route_name = "azure/storage"
    label = "Prowler Azure Storage"
    service_selector = "storage"
