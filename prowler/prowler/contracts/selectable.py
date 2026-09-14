"""Single-selection CHK.017 contracts over the unchanged CHK.004 seam."""

import threading
from typing import ClassVar, Mapping, cast, get_args

from pyoaev.contracts.contract_config import ContractElement, ContractSelect
from pyoaev.contracts.contract_utils import ContractCardinality

from prowler._core.prowler_client import (
    AwsServiceSelector,
    AzureServiceSelector,
    ComplianceSelector,
    GcpServiceSelector,
    ServiceSelector,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import (
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    ProviderInput,
)

from .base import (
    BaseProwlerContract,
    ClientFactoryPort,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
)
from .registry import stable_contract_id

__all__ = [
    "AwsSelectComplianceContract",
    "AwsSelectServiceContract",
    "AzureSelectComplianceContract",
    "AzureSelectServiceContract",
    "COMPLIANCE_SELECT_CHOICES",
    "COMPLIANCE_SELECT_VALUES",
    "GcpSelectComplianceContract",
    "GcpSelectServiceContract",
    "SERVICE_SELECT_CHOICES",
    "SERVICE_SELECT_VALUES",
    "STATIC_SELECT_LABELS",
]

# Human labels for every offered literal; derivation below never invents values.
STATIC_SELECT_LABELS: Mapping[str, str] = {
    "iam": "IAM",
    "s3": "S3",
    "ec2": "EC2",
    "storage": "Storage",
    "compute": "Compute",
    "cis_3.0_aws": "CIS 3.0 (AWS)",
    "nis2_aws": "NIS2 (AWS)",
    "iso27001_2022_aws": "ISO 27001:2022 (AWS)",
    "mitre_attack_aws": "MITRE ATT&CK (AWS)",
    "cis_3.0_azure": "CIS 3.0 (Azure)",
    "nis2_azure": "NIS2 (Azure)",
    "iso27001_2022_azure": "ISO 27001:2022 (Azure)",
    "mitre_attack_azure": "MITRE ATT&CK (Azure)",
    "cis_3.0_gcp": "CIS 3.0 (GCP)",
    "nis2_gcp": "NIS2 (GCP)",
    "iso27001_2022_gcp": "ISO 27001:2022 (GCP)",
    "mitre_attack_gcp": "MITRE ATT&CK (GCP)",
}

# Single source of truth: exactly the implemented CHK.004 selector literals.
SERVICE_SELECT_VALUES: Mapping[str, tuple[str, ...]] = {
    "aws": get_args(AwsServiceSelector),
    "azure": get_args(AzureServiceSelector),
    "gcp": get_args(GcpServiceSelector),
}

COMPLIANCE_SELECT_VALUES: Mapping[str, tuple[str, ...]] = {
    provider: tuple(
        value
        for value in get_args(ComplianceSelector)
        if value.endswith(f"_{provider}")
    )
    for provider in ("aws", "azure", "gcp")
}

SERVICE_SELECT_CHOICES: Mapping[str, Mapping[str, str]] = {
    provider: {value: STATIC_SELECT_LABELS[value] for value in values}
    for provider, values in SERVICE_SELECT_VALUES.items()
}

COMPLIANCE_SELECT_CHOICES: Mapping[str, Mapping[str, str]] = {
    provider: {value: STATIC_SELECT_LABELS[value] for value in values}
    for provider, values in COMPLIANCE_SELECT_VALUES.items()
}


class SelectableProwlerContract(BaseProwlerContract):
    """Bind each parsed closed selection to the worker thread that parsed it.

    The registry holds one shared instance per contract, but the pinned
    pyoaev 2.260521.0 ``ListenQueue._process_message`` acks each RabbitMQ
    message on receipt and then starts a fresh worker thread for that
    message, so same-contract injections process concurrently against the
    shared instance. Binding the selection to the parsing worker thread
    keeps it private per injection: in production, one injection's
    ``parse_input`` and ``execute`` provably run on that injection's own
    per-message worker thread, and no other injection ever runs on it. On a
    reused thread (direct or test use), the reset at the top of every
    ``parse_input`` preserves the R05 semantics: a failed parse never
    exposes a prior selection.
    """

    select_key: ClassVar[str]
    select_label: ClassVar[str]
    select_values: ClassVar[tuple[str, ...]]
    select_choices: ClassVar[Mapping[str, str]]

    def __init__(self, client_factory: ClientFactoryPort | None = None) -> None:
        """Start the instance with no worker thread holding a selection."""
        super().__init__(client_factory)
        self._selection = threading.local()

    def build_provider_fields(self) -> list[ContractElement]:
        """Append exactly one closed mandatory single select to the fields."""
        fields = super().build_provider_fields()
        fields.append(
            ContractSelect(
                key=self.select_key,
                label=self.select_label,
                mandatory=True,
                cardinality=ContractCardinality.One.value,
                defaultValue=[self.select_values[0]],
                choices=dict(self.select_choices),
            )
        )
        return fields

    def parse_input(self, raw_input: Mapping[str, object]) -> ProviderInput:
        """Validate the closed single select before the strict provider model."""
        # Clear this thread's selection before any rejection path can run,
        # so no early return can expose a selection from an earlier parse.
        self._selection.selected = None
        if "provider" in raw_input:
            raise ContractInputError.from_validation(
                (ContractInputIssue(("provider",), "extra_forbidden"),)
            )
        submitted = raw_input.get(self.select_key)
        if not isinstance(submitted, list) or not submitted:
            raise self._select_input_error("select_missing")
        if len(submitted) > 1:
            raise self._select_input_error("select_multiple")
        element = submitted[0]
        if type(element) is not str or element not in self.select_values:
            raise self._select_input_error("select_unknown_value")
        self._selection.selected = element
        candidate = {
            key: value for key, value in raw_input.items() if key != self.select_key
        }
        return super().parse_input(candidate)

    def _select_input_error(self, error_type: str) -> ContractInputError:
        """Build the single value-free issue for one select rejection."""
        return ContractInputError.from_validation(
            (ContractInputIssue((self.select_key,), error_type),)
        )

    def _held_selection(self) -> str | None:
        """Return the selection held by the current thread, if any."""
        selected = getattr(self._selection, "selected", None)
        return selected if isinstance(selected, str) else None

    def _selection_filter(self, prefix: str, provider: ProviderInput | None) -> str:
        """Render the thread-held selection or the closed unselected marker."""
        selected = self._held_selection()
        if provider is None or selected is None:
            return f"{prefix}=unselected"
        return f"{prefix}={selected}"

    def _require_selection(self) -> str:
        """Return the thread-held selection or reject execution without one."""
        selected = self._held_selection()
        if selected is None:
            raise ValueError(
                f"{self.route_name} requires a parsed selection before execution"
            )
        return selected


class SelectableServiceContract(SelectableProwlerContract):
    """Offer one implemented Prowler service through a closed single select."""

    family = "service"
    select_key = "prowler_service"
    select_label = "Service (select one)"

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Report the held service selection as one closed literal marker."""
        info = super().safe_request_info(provider)
        info["filters"] = self._selection_filter("service", provider)
        return info


class SelectableComplianceContract(SelectableProwlerContract):
    """Offer one implemented framework through a closed single select."""

    family = "compliance"
    select_key = "prowler_compliance"
    select_label = "Compliance framework (select one)"

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Report the held framework selection as one closed literal marker."""
        info = super().safe_request_info(provider)
        info["filters"] = self._selection_filter("compliance", provider)
        return info


class AwsSelectServiceContract(SelectableServiceContract):
    """Select one implemented Prowler AWS service and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("aws/select-service"))
    external_id: ClassVar[str] = "prowler:aws/select-service"
    route_name: ClassVar[str] = "aws/select-service"
    provider = "aws"
    label = "Prowler AWS Selectable Service"
    select_values = SERVICE_SELECT_VALUES["aws"]
    select_choices = SERVICE_SELECT_CHOICES["aws"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed AWS service selection once through the seam."""
        if not isinstance(provider, AwsProviderInput):
            raise ValueError("AWS selectable service requires an AWS provider")
        return self._execute_service(
            config, provider, cast(ServiceSelector, self._require_selection())
        )


class AwsSelectComplianceContract(SelectableComplianceContract):
    """Select one implemented Prowler AWS framework and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("aws/select-compliance"))
    external_id: ClassVar[str] = "prowler:aws/select-compliance"
    route_name: ClassVar[str] = "aws/select-compliance"
    provider = "aws"
    label = "Prowler AWS Selectable Compliance"
    select_values = COMPLIANCE_SELECT_VALUES["aws"]
    select_choices = COMPLIANCE_SELECT_CHOICES["aws"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed AWS framework selection once through the seam."""
        if not isinstance(provider, AwsProviderInput):
            raise ValueError("AWS selectable compliance requires an AWS provider")
        return self._execute_compliance(
            config, provider, cast(ComplianceSelector, self._require_selection())
        )


class AzureSelectServiceContract(SelectableServiceContract):
    """Select one implemented Prowler Azure service and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("azure/select-service"))
    external_id: ClassVar[str] = "prowler:azure/select-service"
    route_name: ClassVar[str] = "azure/select-service"
    provider = "azure"
    label = "Prowler Azure Selectable Service"
    select_values = SERVICE_SELECT_VALUES["azure"]
    select_choices = SERVICE_SELECT_CHOICES["azure"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed Azure service selection once through the seam."""
        if not isinstance(provider, AzureProviderInput):
            raise ValueError("Azure selectable service requires an Azure provider")
        return self._execute_service(
            config, provider, cast(ServiceSelector, self._require_selection())
        )


class AzureSelectComplianceContract(SelectableComplianceContract):
    """Select one implemented Prowler Azure framework and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("azure/select-compliance"))
    external_id: ClassVar[str] = "prowler:azure/select-compliance"
    route_name: ClassVar[str] = "azure/select-compliance"
    provider = "azure"
    label = "Prowler Azure Selectable Compliance"
    select_values = COMPLIANCE_SELECT_VALUES["azure"]
    select_choices = COMPLIANCE_SELECT_CHOICES["azure"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed Azure framework selection once through the seam."""
        if not isinstance(provider, AzureProviderInput):
            raise ValueError("Azure selectable compliance requires an Azure provider")
        return self._execute_compliance(
            config, provider, cast(ComplianceSelector, self._require_selection())
        )


class GcpSelectServiceContract(SelectableServiceContract):
    """Select one implemented Prowler GCP service and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("gcp/select-service"))
    external_id: ClassVar[str] = "prowler:gcp/select-service"
    route_name: ClassVar[str] = "gcp/select-service"
    provider = "gcp"
    label = "Prowler GCP Selectable Service"
    select_values = SERVICE_SELECT_VALUES["gcp"]
    select_choices = SERVICE_SELECT_CHOICES["gcp"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed GCP service selection once through the seam."""
        if not isinstance(provider, GcpProviderInput):
            raise ValueError("GCP selectable service requires a GCP provider")
        return self._execute_service(
            config, provider, cast(ServiceSelector, self._require_selection())
        )


class GcpSelectComplianceContract(SelectableComplianceContract):
    """Select one implemented Prowler GCP framework and run it once."""

    contract_id: ClassVar[str] = str(stable_contract_id("gcp/select-compliance"))
    external_id: ClassVar[str] = "prowler:gcp/select-compliance"
    route_name: ClassVar[str] = "gcp/select-compliance"
    provider = "gcp"
    label = "Prowler GCP Selectable Compliance"
    select_values = COMPLIANCE_SELECT_VALUES["gcp"]
    select_choices = COMPLIANCE_SELECT_CHOICES["gcp"]

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run exactly the parsed GCP framework selection once through the seam."""
        if not isinstance(provider, GcpProviderInput):
            raise ValueError("GCP selectable compliance requires a GCP provider")
        return self._execute_compliance(
            config, provider, cast(ComplianceSelector, self._require_selection())
        )
