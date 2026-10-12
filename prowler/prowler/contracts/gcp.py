"""Executable CHK.009 complete-scope GCP base contract."""

from dataclasses import replace
from typing import ClassVar

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome


class GcpBaseContract(BaseProwlerContract):
    """Run the complete GCP provider scope and retain mapped GCP findings."""

    contract_id: ClassVar[str] = "91344897-632c-518d-ab75-818941b43ae7"
    external_id: ClassVar[str] = "prowler:gcp"
    route_name: ClassVar[str] = "gcp"
    provider = "gcp"
    family = "base"
    label = "Prowler GCP"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered GCP findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        findings = tuple(
            finding.model_copy(update={"cloud_provider": "gcp"})
            for finding in outcome.findings
            if finding.cloud_provider.casefold() == "gcp"
        )
        return replace(outcome, findings=findings)
