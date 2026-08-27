"""Inheritable OpenAEV contract boundary for Prowler assessment routes."""

from __future__ import annotations

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
    ContractText,
    ContractTextArea,
    SupportedLanguage,
)

from prowler._core.cli_engine import CommandResult
from prowler._core.prowler_client import ProwlerClientFactory
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.findings import OpenAevFinding, map_command_result
from prowler.models.provider_inputs import PROVIDER_INPUT_ADAPTER, ProviderInput

ProviderName = Literal["aws", "azure", "gcp", "kubernetes"]
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


@dataclass(frozen=True)
class _FieldSpec:
    key: str
    label: str
    mandatory: bool
    multiline: bool = False


_PROVIDER_FIELDS: dict[ProviderName, tuple[_FieldSpec, ...]] = {
    "aws": (
        _FieldSpec("aws_access_key_id", "AWS access key ID (plaintext)", True),
        _FieldSpec("aws_secret_access_key", "AWS secret access key (plaintext)", True),
        _FieldSpec("aws_account_id", "AWS account ID", True),
        _FieldSpec("aws_region", "AWS region", True),
        _FieldSpec(
            "aws_session_token", "AWS session token (plaintext, optional)", False
        ),
    ),
    "azure": (
        _FieldSpec("azure_tenant_id", "Azure tenant ID", True),
        _FieldSpec("azure_client_id", "Azure client ID", True),
        _FieldSpec("azure_client_secret", "Azure client secret (plaintext)", True),
        _FieldSpec("azure_subscription_id", "Azure subscription ID", True),
        _FieldSpec("azure_provider", "Azure cloud environment", True),
    ),
    "gcp": (
        _FieldSpec(
            "gcp_service_account_json",
            "GCP service-account JSON (plaintext)",
            True,
            True,
        ),
        _FieldSpec("gcp_project_id", "GCP project ID", True),
    ),
    "kubernetes": (
        _FieldSpec(
            "kubernetes_kubeconfig", "Kubernetes kubeconfig (plaintext)", True, True
        ),
        _FieldSpec("kubernetes_context", "Kubernetes context", True),
    ),
}

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
            outputs=ContractBuilder().add_outputs([]).build_outputs(),
            manual=False,
        )

    def build_provider_fields(self) -> list[ContractElement]:
        """Declare exact provider model fields using current plaintext controls."""
        fields: list[ContractElement] = []
        for specification in _PROVIDER_FIELDS[self.provider]:
            field_type = ContractTextArea if specification.multiline else ContractText
            fields.append(
                field_type(
                    key=specification.key,
                    label=specification.label,
                    mandatory=specification.mandatory,
                )
            )
        return fields

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
