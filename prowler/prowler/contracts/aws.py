"""Executable CHK.007 complete-scope AWS base contract."""

from dataclasses import replace
from typing import ClassVar

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome


class AwsBaseContract(BaseProwlerContract):
    """Run the complete AWS provider scope and retain only mapped AWS findings."""

    contract_id: ClassVar[str] = "a0464aa7-9451-54ea-bc00-3e89019a315a"
    external_id: ClassVar[str] = "prowler:aws"
    route_name: ClassVar[str] = "aws"
    provider = "aws"
    family = "base"
    label = "Prowler AWS"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map one complete-scope result, preserving ordered AWS findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        findings = tuple(
            finding.model_copy(update={"cloud_provider": "aws"})
            for finding in outcome.findings
            if finding.cloud_provider.casefold() == "aws"
        )
        return replace(outcome, findings=findings)
