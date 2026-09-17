"""Internal provider form-field declarations for Prowler contracts."""

from dataclasses import dataclass
from typing import Literal

from pyoaev.contracts.contract_config import (
    ContractElement,
    ContractText,
    ContractTextArea,
)

ProviderName = Literal["aws", "azure", "gcp", "kubernetes"]


@dataclass(frozen=True, slots=True)
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
        _FieldSpec("aws_endpoint_url", "AWS endpoint URL (optional)", False),
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


def build_provider_fields(provider: ProviderName) -> list[ContractElement]:
    """Declare exact provider model fields using current plaintext controls."""
    fields: list[ContractElement] = []
    for specification in _PROVIDER_FIELDS[provider]:
        field_type = ContractTextArea if specification.multiline else ContractText
        fields.append(
            field_type(
                key=specification.key,
                label=specification.label,
                mandatory=specification.mandatory,
            )
        )
    return fields
