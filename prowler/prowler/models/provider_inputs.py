"""Strict, secret-safe provider inputs for future OpenAEV form contracts."""

from collections.abc import Mapping
from typing import Annotated, Any, Literal, NoReturn, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    InstanceOf,
    SecretStr,
    TypeAdapter,
    field_validator,
)
from pyoaev.credential import CredentialAttachment, ResolvedSecret


def _reject_blank(value: object) -> object:
    """Reject blank strings before they can enter a provider field."""
    if isinstance(value, str) and not value.strip():
        raise ValueError("value must not be blank")
    return value


NonBlankStr = Annotated[str, BeforeValidator(_reject_blank)]
NonBlankSecretStr = Annotated[SecretStr, BeforeValidator(_reject_blank)]
_AWS_ACCOUNT_ID_PATTERN = r"^[0-9]{12}$"
AwsAccountId = Annotated[
    str, BeforeValidator(_reject_blank), Field(pattern=_AWS_ACCOUNT_ID_PATTERN)
]


def _aws_endpoint_origin(value: str) -> str | None:
    """Reduce a validated AWS endpoint override to scheme and authority."""
    from prowler.injector.failure_taxonomy import _safe_text

    try:
        endpoint = urlsplit(value)
        host = endpoint.hostname
        if endpoint.scheme.lower() not in {"http", "https"} or host is None:
            return None
        normalized_host = host.lower()
        if ":" in normalized_host:
            normalized_host = f"[{normalized_host}]"
        authority = normalized_host
        if endpoint.port is not None:
            authority = f"{authority}:{endpoint.port}"
        return _safe_text(f"{endpoint.scheme.lower()}://{authority}")
    except Exception:
        return None


def _validate_aws_endpoint_url(value: object) -> object:
    """Accept only absolute HTTP(S) endpoints without unsafe URL extras."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("AWS endpoint URL must be a string")
    if not value.strip():
        raise ValueError("AWS endpoint URL must not be blank")
    if any(character.isspace() for character in value):
        raise ValueError("AWS endpoint URL must not contain whitespace")
    if "?" in value or "#" in value:
        raise ValueError("AWS endpoint URL must not include query or fragment")
    try:
        endpoint = urlsplit(value)
        if endpoint.netloc.rsplit("@", maxsplit=1)[-1].endswith(":"):
            raise ValueError("AWS endpoint URL port must not be empty")
        port = endpoint.port
    except ValueError as error:
        raise ValueError("AWS endpoint URL must be valid") from error
    if endpoint.scheme not in {"http", "https"}:
        raise ValueError("AWS endpoint URL must use HTTP or HTTPS")
    if not endpoint.netloc or endpoint.hostname is None:
        raise ValueError("AWS endpoint URL must include a host")
    if endpoint.username is not None or endpoint.password is not None:
        raise ValueError("AWS endpoint URL must not include user information")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("AWS endpoint URL port must be between 1 and 65535")
    return value


def _aws_scope_log_metadata(
    aws_account_id: object, aws_region: object, aws_endpoint_url: str | None
) -> dict[str, object]:
    """Return the log-safe AWS account, region, and endpoint facts."""
    from prowler.injector.failure_taxonomy import _safe_text

    metadata: dict[str, object] = {}
    if isinstance(aws_account_id, str):
        metadata["aws_account_id"] = _safe_text(aws_account_id)
    if isinstance(aws_region, str):
        metadata["aws_region"] = _safe_text(aws_region)
    if aws_endpoint_url is None:
        metadata["aws_endpoint_override_present"] = False
        return metadata
    endpoint = _safe_text(aws_endpoint_url)
    metadata["aws_endpoint_override_present"] = True
    origin = _aws_endpoint_origin(endpoint)
    if origin is not None:
        metadata["aws_endpoint_origin"] = origin
    return metadata


class ImmutableProviderInput(BaseModel):
    """Provider boundary that rejects assignment without retaining its value."""

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    def __setattr__(self, name: str, value: Any) -> NoReturn:
        """Reject all post-construction assignment with a value-free error."""
        raise TypeError("Provider inputs are immutable")


class AwsProviderInput(ImmutableProviderInput):
    """AWS provider form input."""

    provider: Literal["aws"]
    aws_access_key_id: NonBlankStr
    aws_secret_access_key: NonBlankSecretStr
    aws_account_id: AwsAccountId
    aws_region: NonBlankStr
    aws_session_token: NonBlankSecretStr | None = None
    aws_endpoint_url: str | None = None

    @field_validator("aws_endpoint_url", mode="before")
    @classmethod
    def validate_aws_endpoint_url(cls, value: object) -> object:
        """Accept only absolute HTTP(S) endpoints without unsafe URL extras."""
        return _validate_aws_endpoint_url(value)

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this AWS input."""
        metadata = _aws_scope_log_metadata(
            self.aws_account_id, self.aws_region, self.aws_endpoint_url
        )
        metadata["aws_session_token_present"] = self.aws_session_token is not None
        return metadata


class AzureProviderInput(ImmutableProviderInput):
    """Azure provider form input."""

    provider: Literal["azure"]
    azure_tenant_id: NonBlankStr
    azure_client_id: NonBlankStr
    azure_client_secret: NonBlankSecretStr
    azure_subscription_id: NonBlankStr
    azure_provider: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this Azure input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata: dict[str, object] = {
            "azure_tenant_id_present": True,
            "azure_client_id_present": True,
            "azure_client_secret_present": True,
        }
        if isinstance(self.azure_subscription_id, str):
            metadata["azure_subscription_id"] = _safe_text(self.azure_subscription_id)
        if isinstance(self.azure_provider, str):
            metadata["azure_provider"] = _safe_text(self.azure_provider)
        return metadata


class GcpProviderInput(ImmutableProviderInput):
    """GCP provider form input."""

    provider: Literal["gcp"]
    gcp_service_account_json: NonBlankSecretStr
    gcp_project_id: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this GCP input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata: dict[str, object] = {"gcp_credentials_present": True}
        if isinstance(self.gcp_project_id, str):
            metadata["gcp_project_id"] = _safe_text(self.gcp_project_id)
        return metadata


class KubernetesProviderInput(ImmutableProviderInput):
    """Kubernetes provider form input."""

    provider: Literal["kubernetes"]
    kubernetes_kubeconfig: NonBlankSecretStr
    kubernetes_context: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this Kubernetes input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata: dict[str, object] = {"kubernetes_credentials_present": True}
        if isinstance(self.kubernetes_context, str):
            metadata["kubernetes_context"] = _safe_text(self.kubernetes_context)
        return metadata


class CredentialReferenceProviderInput(ImmutableProviderInput):
    """Provider input whose credential is resolved from an inject reference.

    It keeps only the non-credential fields of its legacy model: the credential
    itself is resolved just in time from ``credential_attachment``, then held
    in ``resolved_secret`` for the duration of the execution only. Neither is
    ever serialized, and pyoaev keeps the authorisation code and the secret
    values out of their ``repr``.
    """

    credential_attachment: Annotated[CredentialAttachment, Field(exclude=True)]
    resolved_secret: Annotated[
        InstanceOf[ResolvedSecret] | None, Field(exclude=True, repr=False)
    ] = None

    def with_resolved_secret(self, resolved_secret: ResolvedSecret) -> Self:
        """Return a copy holding the secret resolved for this execution."""
        return self.model_copy(update={"resolved_secret": resolved_secret})

    def reference_log_metadata(self) -> dict[str, object]:
        """Return the log-safe facts about the credential reference."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata: dict[str, object] = {
            "credential_reference_present": True,
            "credential_reference": _safe_text(self.credential_attachment.reference),
        }
        if self.resolved_secret is not None:
            metadata["credential_secret_type"] = self.resolved_secret.secret_type.value
        return metadata


class AwsReferenceProviderInput(CredentialReferenceProviderInput):
    """AWS provider form input whose credential comes from a reference."""

    provider: Literal["aws"]
    aws_account_id: AwsAccountId
    aws_region: NonBlankStr
    aws_endpoint_url: str | None = None

    @field_validator("aws_endpoint_url", mode="before")
    @classmethod
    def validate_aws_endpoint_url(cls, value: object) -> object:
        """Accept only absolute HTTP(S) endpoints without unsafe URL extras."""
        return _validate_aws_endpoint_url(value)

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this AWS input."""
        metadata = _aws_scope_log_metadata(
            self.aws_account_id, self.aws_region, self.aws_endpoint_url
        )
        metadata.update(self.reference_log_metadata())
        return metadata


class AzureReferenceProviderInput(CredentialReferenceProviderInput):
    """Azure provider form input whose credential comes from a reference."""

    provider: Literal["azure"]
    azure_subscription_id: NonBlankStr
    azure_provider: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this Azure input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata = self.reference_log_metadata()
        if isinstance(self.azure_subscription_id, str):
            metadata["azure_subscription_id"] = _safe_text(self.azure_subscription_id)
        if isinstance(self.azure_provider, str):
            metadata["azure_provider"] = _safe_text(self.azure_provider)
        return metadata


class GcpReferenceProviderInput(CredentialReferenceProviderInput):
    """GCP provider form input whose credential comes from a reference."""

    provider: Literal["gcp"]
    gcp_project_id: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this GCP input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata = self.reference_log_metadata()
        if isinstance(self.gcp_project_id, str):
            metadata["gcp_project_id"] = _safe_text(self.gcp_project_id)
        return metadata


class KubernetesReferenceProviderInput(CredentialReferenceProviderInput):
    """Kubernetes provider form input whose credential comes from a reference.

    No credential type is mapped to Kubernetes, so the resolution of such a
    reference is expected to fail as incompatible rather than fall back on the
    kubeconfig field.
    """

    provider: Literal["kubernetes"]
    kubernetes_context: NonBlankStr

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this Kubernetes input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata = self.reference_log_metadata()
        if isinstance(self.kubernetes_context, str):
            metadata["kubernetes_context"] = _safe_text(self.kubernetes_context)
        return metadata


_PROVIDER_DISCRIMINATOR = "provider"
LegacyProviderInput = Annotated[
    AwsProviderInput | AzureProviderInput | GcpProviderInput | KubernetesProviderInput,
    Field(discriminator=_PROVIDER_DISCRIMINATOR),
]
ReferenceProviderInput = Annotated[
    AwsReferenceProviderInput
    | AzureReferenceProviderInput
    | GcpReferenceProviderInput
    | KubernetesReferenceProviderInput,
    Field(discriminator=_PROVIDER_DISCRIMINATOR),
]
ProviderInput = LegacyProviderInput | ReferenceProviderInput

# Per-provider model pairs, for type gates that accept both credential paths.
AWS_PROVIDER_INPUTS = (AwsProviderInput, AwsReferenceProviderInput)
AZURE_PROVIDER_INPUTS = (AzureProviderInput, AzureReferenceProviderInput)
GCP_PROVIDER_INPUTS = (GcpProviderInput, GcpReferenceProviderInput)
KUBERNETES_PROVIDER_INPUTS = (KubernetesProviderInput, KubernetesReferenceProviderInput)

PROVIDER_INPUT_ADAPTER: TypeAdapter[LegacyProviderInput] = TypeAdapter(
    LegacyProviderInput,
    config=ConfigDict(hide_input_in_errors=True),
)
REFERENCE_PROVIDER_INPUT_ADAPTER: TypeAdapter[ReferenceProviderInput] = TypeAdapter(
    ReferenceProviderInput,
    config=ConfigDict(hide_input_in_errors=True),
)

# The legacy credential text fields are exactly the legacy model fields that
# the reference model does not keep, so both stay derived from one place.
LEGACY_CREDENTIAL_KEYS: Mapping[str, frozenset[str]] = {
    provider: frozenset(legacy.model_fields) - frozenset(reference.model_fields)
    for provider, (legacy, reference) in (
        ("aws", AWS_PROVIDER_INPUTS),
        ("azure", AZURE_PROVIDER_INPUTS),
        ("gcp", GCP_PROVIDER_INPUTS),
        ("kubernetes", KUBERNETES_PROVIDER_INPUTS),
    )
}


def validate_provider_input(
    candidate: Mapping[str, object],
    credential_attachment: CredentialAttachment | None = None,
) -> ProviderInput:
    """Validate one form candidate on the legacy or the reference path.

    Without an attachment, the strict legacy model is validated unchanged.
    With one, the legacy credential fields of the provider are removed from
    the candidate before validation, so they are ignored even when filled and
    are never combined with the referenced credential. A candidate that does
    not match the selected model raises the pydantic ``ValidationError``.
    """
    if credential_attachment is None:
        return PROVIDER_INPUT_ADAPTER.validate_python(candidate)
    ignored_keys = LEGACY_CREDENTIAL_KEYS.get(str(candidate.get("provider")), ())
    reference_candidate = {
        key: value for key, value in candidate.items() if key not in ignored_keys
    }
    reference_candidate["credential_attachment"] = credential_attachment
    return REFERENCE_PROVIDER_INPUT_ADAPTER.validate_python(reference_candidate)
