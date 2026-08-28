"""Inheritable OpenAEV contract boundary for Prowler assessment routes."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Literal, Protocol
from uuid import UUID

from pydantic import ValidationError
from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractOutputType,
    SupportedLanguage,
)

from prowler._core.cli_engine import CommandResult
from prowler._core.prowler_client import ProwlerClientFactory, ServiceSelector
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.findings import (
    OcsfDecodeError,
    OcsfMappingError,
    OcsfPreviewRecord,
    OpenAevFinding,
    map_command_result_with_evidence,
)
from prowler.models.provider_inputs import (
    PROVIDER_INPUT_ADAPTER,
    AwsProviderInput,
    AzureProviderInput,
    GcpProviderInput,
    KubernetesProviderInput,
    ProviderInput,
)
from prowler.services.output_trace import generate

from .provider_fields import ProviderName as ProviderName
from .provider_fields import build_provider_fields as _build_provider_fields

__all__ = [
    "BaseProwlerContract",
    "ClientFactoryPort",
    "ContractExecutionOutcome",
    "ContractInputError",
    "ContractInputIssue",
    "ProviderName",
    "RouteFamily",
]

RouteFamily = Literal["base", "service", "compliance"]


class ClientFactoryPort(Protocol):
    """Narrow synchronous CHK.004 seam used by contract subclasses."""

    def run(
        self,
        config: ProwlerConfig,
        provider: ProviderInput,
        *,
        check_filters: Sequence[str] = (),
        service_selector: ServiceSelector | None = None,
    ) -> CommandResult:
        """Run one assessment and return the exact command result."""


@dataclass(frozen=True)
class ContractInputIssue:
    """Value-free location and category for one rejected form input."""

    location: tuple[str, ...]
    error_type: str


class ContractInputError(ValueError):
    """Safe structured failure at the OpenAEV form boundary."""

    def __init__(
        self,
        issues: tuple[ContractInputIssue, ...],
        *,
        _trusted_issues: bool = False,
    ) -> None:
        """Retain only safe structural issues."""
        self.issues = issues
        self.issues_are_trusted = _trusted_issues
        summary = ", ".join(
            f"{'.'.join(issue.location)}:{issue.error_type}" for issue in issues
        )
        super().__init__(f"Invalid Prowler contract input ({summary})")

    @classmethod
    def from_validation(
        cls, issues: tuple[ContractInputIssue, ...]
    ) -> ContractInputError:
        """Mark issues produced by this contract's strict validation boundary."""
        return cls(issues, _trusted_issues=True)


@dataclass(frozen=True)
class ContractExecutionOutcome:
    """Typed findings and bounded evidence plus the unchanged command result."""

    command_result: CommandResult
    findings: tuple[OpenAevFinding, ...] = ()
    raw_record_count: int = 0
    raw_output_bytes: int = 0
    raw_preview: tuple[OcsfPreviewRecord, ...] = ()
    error: Any | None = None

    def __post_init__(self) -> None:
        """Enforce the preview-count boundary even for custom contract outcomes."""
        object.__setattr__(self, "raw_preview", tuple(self.raw_preview[:10]))


_CONTRACT_CONFIG = ContractConfig(
    type="openaev_prowler",
    label={SupportedLanguage.en: "Prowler"},
    color_dark="#455A64",
    color_light="#455A64",
    expose=True,
)


class BaseProwlerContract(ABC):
    """Base declaration, parser, form builder, and synchronous execution template."""

    contract_id: ClassVar[str]
    external_id: ClassVar[str]
    provider: ClassVar[ProviderName]
    family: ClassVar[RouteFamily]
    label: ClassVar[str]
    check_filters: ClassVar[tuple[str, ...]] = ()

    @property
    @abstractmethod
    def route_name(self) -> str:
        """Return the canonical route name supplied by a concrete subclass."""

    def __init__(self, client_factory: ClientFactoryPort | None = None) -> None:
        """Inject the CHK.004 factory without retaining any form payload."""
        self._client_factory = client_factory or ProwlerClientFactory()

    def build_contract(self) -> Contract:
        """Build one concrete OpenAEV contract from subclass route metadata."""
        UUID(self.contract_id)
        if not self.external_id.strip():
            raise ValueError("external_id must not be blank")
        return Contract(
            contract_id=self.contract_id,
            external_id=self.external_id,
            config=_CONTRACT_CONFIG,
            label={SupportedLanguage.en: self.label},
            fields=ContractBuilder()
            .add_fields(self.build_provider_fields())
            .build_fields(),
            outputs=ContractBuilder().add_outputs(self.build_outputs()).build_outputs(),
            manual=False,
        )

    def build_provider_fields(self) -> list[ContractElement]:
        """Declare exact provider model fields using current plaintext controls."""
        return _build_provider_fields(self.provider)

    def build_outputs(self) -> list[ContractOutputElement]:
        """Declare preserved text findings and FAILED vulnerability projections."""
        labels = list(dict.fromkeys(("prowler", self.provider, self.route_name)))
        return [
            ContractOutputElement(
                type=ContractOutputType.Text.value,
                field="findings",
                labels=labels,
                isFindingCompatible=False,
                isMultiple=True,
            ),
            ContractOutputElement(
                type=ContractOutputType.Vulnerability.value,
                field="vulnerabilities",
                labels=labels,
                isFindingCompatible=True,
                isMultiple=True,
            ),
        ]

    def output_payload(
        self, findings: Sequence[OpenAevFinding]
    ) -> dict[str, list[Any]]:
        """Serialize every finding and project only failed findings."""
        return {
            "findings": [
                json.dumps(
                    finding.model_dump(mode="json"),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                for finding in findings
            ],
            "vulnerabilities": [
                self._vulnerability(finding)
                for finding in findings
                if finding.expectation_result == "FAILED"
            ],
        }

    def _provider_findings(
        self, findings: Sequence[OpenAevFinding]
    ) -> tuple[OpenAevFinding, ...]:
        """Retain source order and normalize findings for this contract provider."""
        return tuple(
            finding.model_copy(update={"cloud_provider": self.provider})
            for finding in findings
            if finding.cloud_provider.casefold() == self.provider
        )

    @staticmethod
    def output_trace_config() -> dict[str, object]:
        """Return the common flattened-field trace contract."""
        return {
            "columns": [
                {"title": "Check", "path": "value"},
                {"title": "Status", "path": "expectation_result"},
                {"title": "Severity", "path": "severity"},
                {"title": "Asset", "path": "asset_name"},
                {"title": "Region", "path": "region"},
                {"title": "Account", "path": "cloud_account"},
            ],
            "options": {"max_rows": 50, "max_cell_length": 120},
        }

    def safe_request_info(self, provider: ProviderInput | None) -> dict[str, object]:
        """Allowlist non-credential context from a parsed provider model."""
        info: dict[str, object] = {
            "route": self.route_name,
            "filters": ", ".join(self.check_filters) if self.check_filters else "all",
        }
        if isinstance(provider, AwsProviderInput):
            info.update(account=provider.aws_account_id, region=provider.aws_region)
        elif isinstance(provider, AzureProviderInput):
            info.update(
                subscription=provider.azure_subscription_id,
                requested_provider=provider.azure_provider,
            )
        elif isinstance(provider, GcpProviderInput):
            info["project"] = provider.gcp_project_id
        elif isinstance(provider, KubernetesProviderInput):
            info["context"] = provider.kubernetes_context
        return info

    def render_trace(
        self,
        provider: ProviderInput | None,
        findings: Sequence[OpenAevFinding],
        duration: int,
        *,
        raw_record_count: int = 0,
        raw_output_bytes: int = 0,
        raw_preview: Sequence[OcsfPreviewRecord] = (),
        is_error: bool = False,
        error_message: str = "",
    ) -> str:
        """Render safe request context and flattened findings through Rich."""
        return generate(
            route_name=self.route_name,
            provider_name=self.provider,
            request_info=self.safe_request_info(provider),
            findings=findings,
            raw_record_count=raw_record_count,
            raw_output_bytes=raw_output_bytes,
            raw_preview=raw_preview,
            duration=duration,
            trace_config=self.output_trace_config(),
            is_error=is_error,
            error_message=error_message,
        )

    @staticmethod
    def _vulnerability(finding: OpenAevFinding) -> dict[str, str]:
        """Project one failed finding without claiming an OpenAEV asset UUID."""
        remediation = f"Remediation: {finding.remediation}"
        if finding.remediation_url is not None:
            remediation += f" ({finding.remediation_url})"
        compliance = ", ".join(finding.compliance_tags)
        details = "\n".join(
            (
                finding.description,
                remediation,
                f"Severity: {finding.severity} ({finding.severity_weight})",
                (
                    f"Cloud: provider={finding.cloud_provider}; "
                    f"account={finding.cloud_account}; region={finding.region}; "
                    f"resource={finding.asset_name} [{finding.asset_reference}]; "
                    f"compliance={compliance}"
                ),
            )
        )
        return {
            "name": finding.value,
            "status": "VULNERABLE",
            "details": details,
        }

    def parse_input(self, raw_input: Mapping[str, object]) -> ProviderInput:
        """Convert ephemeral form values immediately into the strict CHK.002 model."""
        if "provider" in raw_input:
            raise ContractInputError.from_validation(
                (ContractInputIssue(("provider",), "extra_forbidden"),)
            )
        candidate = dict(raw_input)
        if self.provider == "aws":
            for field in ("aws_session_token", "aws_endpoint_url"):
                value = candidate.get(field)
                if type(value) is str and value == "":
                    candidate[field] = None
        candidate["provider"] = self.provider
        try:
            return PROVIDER_INPUT_ADAPTER.validate_python(candidate)
        except ValidationError as error:
            issues = tuple(
                ContractInputIssue(
                    tuple(str(part) for part in item["loc"]),
                    item["type"],
                )
                for item in error.errors(
                    include_url=False, include_context=False, include_input=False
                )
            )
            raise ContractInputError.from_validation(issues) from None

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run once, preserve failures unchanged, and map successful raw output."""
        result = self._client_factory.run(
            config, provider, check_filters=self.check_filters
        )
        if result.error is not None or result.return_code != 0:
            return ContractExecutionOutcome(command_result=result, error=result.error)
        try:
            mapping = map_command_result_with_evidence(result)
        except (OcsfDecodeError, OcsfMappingError) as error:
            return ContractExecutionOutcome(command_result=result, error=error)
        return ContractExecutionOutcome(
            command_result=result,
            findings=mapping.findings,
            raw_record_count=mapping.raw_record_count,
            raw_output_bytes=mapping.raw_output_bytes,
            raw_preview=mapping.raw_preview,
        )
