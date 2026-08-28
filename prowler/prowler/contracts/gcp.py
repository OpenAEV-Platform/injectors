"""Executable complete-scope and service-specific GCP contracts."""

from dataclasses import replace
from typing import ClassVar

from prowler._core.prowler_client import GcpServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import GcpProviderInput, ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome, RouteFamily


class GcpBaseContract(BaseProwlerContract):
    """Run the complete GCP provider scope and retain mapped GCP findings."""

    contract_id: ClassVar[str] = "91344897-632c-518d-ab75-818941b43ae7"
    external_id: ClassVar[str] = "prowler:gcp"
    route_name: ClassVar[str] = "gcp"
    provider = "gcp"
    family: ClassVar[RouteFamily] = "base"
    label = "Prowler GCP"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered GCP findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        return replace(outcome, findings=self._provider_findings(outcome.findings))


class GcpServiceContract(GcpBaseContract):
    """Execute one route-owned GCP service selector through the CHK.004 seam."""

    family = "service"
    service_selector: ClassVar[GcpServiceSelector]

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Identify the service through safe route metadata, never form input."""
        info = super().safe_request_info(provider)
        info["filters"] = f"service={self.service_selector}"
        return info

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Reject invalid route combinations before one service-specific client call."""
        if self.service_selector not in ("iam", "compute"):
            raise ValueError("unsupported GCP service selector")
        if not isinstance(provider, GcpProviderInput):
            raise ValueError("GCP service selector requires a GCP provider")
        return self._execute_service(config, provider, self.service_selector)


class GcpIamContract(GcpServiceContract):
    """Run only Prowler GCP IAM checks."""

    contract_id = "0684cf36-b1fc-5cdf-926e-e4d0c9f90aea"
    external_id = "prowler:gcp/iam"
    route_name = "gcp/iam"
    label = "Prowler GCP IAM"
    service_selector = "iam"


class GcpComputeContract(GcpServiceContract):
    """Run only Prowler GCP Compute checks."""

    contract_id = "b50c4b61-1c03-55ef-80eb-2a45c000264d"
    external_id = "prowler:gcp/compute"
    route_name = "gcp/compute"
    label = "Prowler GCP Compute"
    service_selector = "compute"
