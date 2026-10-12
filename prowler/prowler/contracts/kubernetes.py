"""Executable CHK.010 complete-scope Kubernetes base contract."""

from dataclasses import replace
from typing import ClassVar

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

from .base import BaseProwlerContract, ContractExecutionOutcome


class KubernetesBaseContract(BaseProwlerContract):
    """Run the complete Kubernetes scope and retain mapped Kubernetes findings."""

    contract_id: ClassVar[str] = "3375520f-a6f7-56a3-99d3-ae0517de6b7b"
    external_id: ClassVar[str] = "prowler:kubernetes"
    route_name: ClassVar[str] = "kubernetes"
    provider = "kubernetes"
    family = "base"
    label = "Prowler Kubernetes"
    check_filters = ()

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Map once, preserving ordered Kubernetes findings only."""
        outcome = super().execute(config, provider)
        if outcome.error is not None or outcome.command_result.return_code != 0:
            return outcome
        return replace(outcome, findings=self._provider_findings(outcome.findings))
