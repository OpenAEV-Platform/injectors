"""Shared fixed-selector execution for executable compliance routes."""

from typing import ClassVar

from prowler._core.prowler_client import ComplianceSelector, ServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ProviderName,
    RouteFamily,
)


class FixedComplianceContract(BaseProwlerContract):
    """Route one internal provider-owned selector through the CHK.004 seam."""

    family: ClassVar[RouteFamily] = "compliance"
    compliance_selector: ClassVar[ComplianceSelector]
    compliance_by_provider: ClassVar[dict[ProviderName, ComplianceSelector]]
    framework_name: ClassVar[str]

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Identify fixed selection through safe route metadata only."""
        info = super().safe_request_info(provider)
        info["filters"] = f"compliance={self.compliance_selector}"
        return info

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Reject unsupported route metadata before one compliance client call."""
        if (
            self.compliance_by_provider.get(self.provider) != self.compliance_selector
            or provider.provider != self.provider
        ):
            raise ValueError(f"unsupported {self.framework_name} compliance selection")
        return self._execute_compliance(config, provider, self.compliance_selector)


class FixedServiceContract(BaseProwlerContract):
    """Route one provider-owned service selector through the CHK.004 seam."""

    family: ClassVar[RouteFamily] = "service"
    service_selector: ClassVar[ServiceSelector]
    service_selectors: ClassVar[tuple[ServiceSelector, ...]]
    provider_input_type: ClassVar[type[object]]
    provider_label: ClassVar[str]
    provider_article: ClassVar[str]

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Identify fixed selection through safe route metadata only."""
        info = super().safe_request_info(provider)
        info["filters"] = f"service={self.service_selector}"
        return info

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Reject unsupported route metadata before one service client call."""
        if self.service_selector not in self.service_selectors:
            raise ValueError(f"unsupported {self.provider_label} service selector")
        if not isinstance(provider, self.provider_input_type):
            raise ValueError(
                f"{self.provider_label} service selector requires "
                f"{self.provider_article} {self.provider_label} provider"
            )
        return self._execute_service(config, provider, self.service_selector)
