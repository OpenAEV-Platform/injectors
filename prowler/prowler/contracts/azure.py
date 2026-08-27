"""Executable CHK.008 complete-scope Azure base contract."""

from dataclasses import replace
from typing import ClassVar

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome


class AzureBaseContract(BaseProwlerContract):
    """Run the complete Azure provider scope and retain mapped Azure findings."""

    contract_id: ClassVar[str] = "00558d49-06ee-5a6f-80e6-4dae205be992"
    external_id: ClassVar[str] = "prowler:azure"
    route_name: ClassVar[str] = "azure"
    provider = "azure"
    family = "base"
    label = "Prowler Azure"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered Azure findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        findings = tuple(
            finding.model_copy(update={"cloud_provider": "azure"})
            for finding in outcome.findings
            if finding.cloud_provider.casefold() == "azure"
        )
        return replace(outcome, findings=findings)
