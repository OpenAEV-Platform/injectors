"""Executable complete-scope and service-specific Azure contracts."""

from dataclasses import replace
from typing import ClassVar

from prowler._core.prowler_client import AzureServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AzureProviderInput, ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome, RouteFamily


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
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        return replace(outcome, findings=self._provider_findings(outcome.findings))


class AzureServiceContract(AzureBaseContract):
    """Execute one route-owned Azure service selector through the CHK.004 seam."""

    family = "service"
    service_selector: ClassVar[AzureServiceSelector]

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Identify the service through safe route metadata, never form input."""
        info = super().safe_request_info(provider)
        info["filters"] = f"service={self.service_selector}"
        return info

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Reject invalid route combinations before one service-specific client call."""
        if self.service_selector not in ("iam", "storage"):
            raise ValueError("unsupported Azure service selector")
        if not isinstance(provider, AzureProviderInput):
            raise ValueError("Azure service selector requires an Azure provider")
        return self._execute_service(config, provider, self.service_selector)


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
