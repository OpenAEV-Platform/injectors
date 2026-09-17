"""Strict, secret-safe provider inputs for future OpenAEV form contracts."""

from typing import Annotated, Any, Literal, NoReturn
from urllib.parse import urlsplit

from pydantic import (BaseModel, BeforeValidator, ConfigDict, Field, SecretStr,
                      TypeAdapter, field_validator)


def _reject_blank(value: object) -> object:
    """Reject blank strings before they can enter a provider field."""
    if isinstance(value, str) and not value.strip():
        raise ValueError("value must not be blank")
    return value


NonBlankStr = Annotated[str, BeforeValidator(_reject_blank)]
NonBlankSecretStr = Annotated[SecretStr, BeforeValidator(_reject_blank)]
AwsAccountId = Annotated[
    str, BeforeValidator(_reject_blank), Field(pattern=r"^[0-9]{12}$")
]


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

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

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


class AzureProviderInput(ImmutableProviderInput):
    """Azure provider form input."""

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    provider: Literal["azure"]
    azure_tenant_id: NonBlankStr
    azure_client_id: NonBlankStr
    azure_client_secret: NonBlankSecretStr
    azure_subscription_id: NonBlankStr
    azure_provider: NonBlankStr


class GcpProviderInput(ImmutableProviderInput):
    """GCP provider form input."""

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    provider: Literal["gcp"]
    gcp_service_account_json: NonBlankSecretStr
    gcp_project_id: NonBlankStr


class KubernetesProviderInput(ImmutableProviderInput):
    """Kubernetes provider form input."""

    model_config = ConfigDict(
        extra="forbid", strict=True, hide_input_in_errors=True, frozen=True
    )

    provider: Literal["kubernetes"]
    kubernetes_kubeconfig: NonBlankSecretStr
    kubernetes_context: NonBlankStr


ProviderInput = Annotated[
    AwsProviderInput | AzureProviderInput | GcpProviderInput | KubernetesProviderInput,
    Field(discriminator="provider"),
]

PROVIDER_INPUT_ADAPTER: TypeAdapter[ProviderInput] = TypeAdapter(
    ProviderInput,
    config=ConfigDict(hide_input_in_errors=True),
)
