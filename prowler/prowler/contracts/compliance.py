"""Shared fixed-selector execution for executable compliance routes."""

from typing import ClassVar

from prowler._core.prowler_client import ComplianceSelector
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
