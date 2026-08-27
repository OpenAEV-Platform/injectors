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
from prowler._core.prowler_client import ProwlerClientFactory
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.findings import OpenAevFinding, map_command_result
from prowler.models.provider_inputs import PROVIDER_INPUT_ADAPTER, ProviderInput

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
    ) -> CommandResult:
        """Run one assessment and return the exact command result."""


@dataclass(frozen=True)
class ContractInputIssue:
    """Value-free location and category for one rejected form input."""

    location: tuple[str, ...]
    error_type: str


class ContractInputError(ValueError):
    """Safe structured failure at the OpenAEV form boundary."""

    def __init__(self, issues: tuple[ContractInputIssue, ...]) -> None:
        """Retain only safe structural issues."""
        self.issues = issues
        summary = ", ".join(
            f"{'.'.join(issue.location)}:{issue.error_type}" for issue in issues
        )
        super().__init__(f"Invalid Prowler contract input ({summary})")


@dataclass(frozen=True)
class ContractExecutionOutcome:
    """Typed findings plus the unchanged CHK.003/CHK.004 result boundary."""

    command_result: CommandResult
    findings: tuple[OpenAevFinding, ...] = ()
    error: Any | None = None


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

    def execution_trace(self, findings: Sequence[OpenAevFinding]) -> str:
        """Render a deterministic plain-text summary of flattened findings."""
        counts = {
            status: sum(finding.expectation_result == status for finding in findings)
            for status in ("SUCCESS", "FAILED", "IGNORED")
        }
        lines = [
            f"Route: {self.route_name}",
            (
                f"Findings: {len(findings)} "
                f"(SUCCESS={counts['SUCCESS']} FAILED={counts['FAILED']} "
                f"IGNORED={counts['IGNORED']})"
            ),
        ]
        for index, finding in enumerate(findings, start=1):
            flattened = finding.model_dump(mode="json")
            rendered = " | ".join(
                f"{field}={self._trace_value(flattened[field])}"
                for field in OpenAevFinding.model_fields
            )
            lines.append(f"{index}. {rendered}")
        return "\n".join(lines)

    @staticmethod
    def _trace_value(value: object) -> str:
        """Render one flattened model value without terminal styling."""
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        return "" if value is None else str(value)

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
            raise ContractInputError(
                (ContractInputIssue(("provider",), "extra_forbidden"),)
            )
        candidate = {"provider": self.provider, **raw_input}
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
            raise ContractInputError(issues) from None

    def execute(
        self, config: ProwlerConfig, provider: ProviderInput
    ) -> ContractExecutionOutcome:
        """Run once, preserve failures unchanged, and map successful raw output."""
        result = self._client_factory.run(
            config, provider, check_filters=self.check_filters
        )
        if result.error is not None or result.return_code != 0:
            return ContractExecutionOutcome(command_result=result, error=result.error)
        return ContractExecutionOutcome(
            command_result=result,
            findings=map_command_result(result),
        )
