"""Strict, secret-safe provider inputs for future OpenAEV form contracts."""

from typing import Annotated, Any, Literal, NoReturn
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    field_validator,
)


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

    def safe_log_metadata(self) -> dict[str, object]:
        """Return the log-safe metadata facts for this AWS input."""
        from prowler.injector.failure_taxonomy import _safe_text

        metadata: dict[str, object] = {}
        if isinstance(self.aws_account_id, str):
            metadata["aws_account_id"] = _safe_text(self.aws_account_id)
        if isinstance(self.aws_region, str):
            metadata["aws_region"] = _safe_text(self.aws_region)
        metadata["aws_session_token_present"] = self.aws_session_token is not None
        if self.aws_endpoint_url is None:
            metadata["aws_endpoint_override_present"] = False
            return metadata
        endpoint = _safe_text(self.aws_endpoint_url)
        metadata["aws_endpoint_override_present"] = True
        origin = _aws_endpoint_origin(endpoint)
        if origin is not None:
            metadata["aws_endpoint_origin"] = origin
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


_PROVIDER_DISCRIMINATOR = "provider"
ProviderInput = Annotated[
    AwsProviderInput | AzureProviderInput | GcpProviderInput | KubernetesProviderInput,
    Field(discriminator=_PROVIDER_DISCRIMINATOR),
]

PROVIDER_INPUT_ADAPTER: TypeAdapter[ProviderInput] = TypeAdapter(
    ProviderInput,
    config=ConfigDict(hide_input_in_errors=True),
)
