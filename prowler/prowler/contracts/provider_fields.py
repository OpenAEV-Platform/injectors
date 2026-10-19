"""Internal provider form-field declarations for Prowler contracts."""

from dataclasses import dataclass
from typing import Literal

from pyoaev.contracts.contract_config import (
    ContractElement,
    ContractText,
    ContractTextArea,
)
from pyoaev.credential.utils import build_single_referenced_credential_element

ProviderName = Literal["aws", "azure", "gcp", "kubernetes"]
# Route identity also admits the universal route's "all" meta-provider,
# which selects a credential provider at parse time and has no fields itself.
RouteProviderName = Literal["aws", "azure", "gcp", "kubernetes", "all"]

# pyoaev fixes this key on every ContractReferencedCredential element, so the
# parse boundary can strip it by name without trusting the submitted form.
CREDENTIAL_REFERENCE_KEY = "credential_reference"

PROVIDER_LABELS: dict[ProviderName, str] = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "kubernetes": "Kubernetes",
}

# Kubernetes has no credential type on the platform, so its credentials are
# always the legacy fields.
CREDENTIAL_MANAGER_PROVIDERS: tuple[ProviderName, ...] = ("aws", "azure", "gcp")


@dataclass(frozen=True, slots=True)
class _FieldSpec:
    key: str
    label: str
    mandatory: bool
    multiline: bool = False
    # A field a stored credential provides: never required by the form, since
    # a credential reference replaces it. The parse boundary requires it
    # without a reference.
    from_credential: bool = True


_PROVIDER_FIELDS: dict[ProviderName, tuple[_FieldSpec, ...]] = {
    "aws": (
        _FieldSpec("aws_access_key_id", "AWS access key ID (plaintext)", True),
        _FieldSpec("aws_secret_access_key", "AWS secret access key (plaintext)", True),
        # No credential carries the account or the endpoint override.
        _FieldSpec("aws_account_id", "AWS account ID", True, False, False),
        _FieldSpec("aws_region", "AWS region", True),
        _FieldSpec(
            "aws_endpoint_url", "AWS endpoint URL (optional)", False, False, False
        ),
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
        # No credential type maps to Kubernetes: its credentials are manual.
        _FieldSpec(
            "kubernetes_kubeconfig",
            "Kubernetes kubeconfig (plaintext)",
            True,
            True,
            False,
        ),
        _FieldSpec("kubernetes_context", "Kubernetes context", True, False, False),
    ),
}


def build_provider_field(
    specification: "_FieldSpec",
    *,
    mandatory: bool,
    condition: dict[str, str | list[str]] | None = None,
) -> ContractElement:
    """Declare one provider field, optionally shown and required on a condition.

    A conditional field is never mandatory alone: it is required only when its
    condition holds, so a hidden field never blocks an inject.
    """
    field_type = ContractTextArea if specification.multiline else ContractText
    element = field_type(
        key=specification.key,
        label=specification.label,
        mandatory=mandatory and condition is None,
    )
    if condition is not None:
        element.visibleConditionFields = list(condition)
        element.visibleConditionValues = dict(condition)
        if mandatory:
            element.mandatoryConditionFields = list(condition)
            element.mandatoryConditionValues = dict(condition)
    return element


def build_provider_fields(provider: ProviderName) -> list[ContractElement]:
    """Declare exact provider model fields using current plaintext controls.

    The credential picker and the legacy credential fields are shown together.
    The form cannot require either alone, so the fields a credential provides
    are not required here: an inject with a credential reference uses it, and
    one without is validated against the legacy fields. A provider with a
    platform credential type leads with the picker; Kubernetes, which has none,
    keeps it last.
    """
    fields = [
        build_provider_field(
            specification,
            mandatory=specification.mandatory and not specification.from_credential,
        )
        for specification in _PROVIDER_FIELDS[provider]
    ]
    reference = build_single_referenced_credential_element(provider)
    if provider in CREDENTIAL_MANAGER_PROVIDERS:
        return [reference, *fields]
    return [*fields, reference]
