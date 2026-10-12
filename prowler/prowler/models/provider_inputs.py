"""Strict, secret-safe provider inputs for future OpenAEV form contracts."""

from dataclasses import dataclass
from typing import Annotated, Any, Literal, NoReturn
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
    field_validator,
)


def _reject_blank(value: object) -> object:
    """Reject blank or NUL-bearing strings before they enter a provider field."""
    if isinstance(value, str) and not value.strip():
        raise ValueError("value must not be blank")
    if isinstance(value, str) and "\x00" in value:
        raise ValueError("value must not contain NUL characters")
    return value


NonBlankStr = Annotated[str, BeforeValidator(_reject_blank)]
NonBlankSecretStr = Annotated[SecretStr, BeforeValidator(_reject_blank)]
# The cloud environments accepted by Prowler's --azure-region option.
AzureCloudEnvironment = Literal["AzureCloud", "AzureChinaCloud", "AzureUSGovernment"]


# Kubeconfig settings allowed for injection-supplied credentials. Anything else,
# including exec and auth-provider plugins and every file-path setting, could run
# commands or read files on the injector host when Prowler loads the kubeconfig.
_KUBECONFIG_TOP_LEVEL_KEYS = frozenset(
    {
        "apiVersion",
        "kind",
        "clusters",
        "contexts",
        "users",
        "current-context",
        "preferences",
    }
)
_KUBECONFIG_ENTRY_KEYS = {
    "clusters": (
        "cluster",
        frozenset(
            {
                "server",
                "certificate-authority-data",
                "insecure-skip-tls-verify",
                "tls-server-name",
            }
        ),
    ),
    "contexts": ("context", frozenset({"cluster", "user", "namespace"})),
    "users": (
        "user",
        frozenset({"token", "client-certificate-data", "client-key-data"}),
    ),
}
_UNSAFE_KUBECONFIG = "kubeconfig contains unsupported settings"


def _is_scalar_setting(key: str, value: object) -> bool:
    if key == "insecure-skip-tls-verify":
        return isinstance(value, bool)
    return isinstance(value, str)


def _check_kubeconfig_entries(
    section: object, entry_key: str, allowed: frozenset[str]
) -> None:
    if section is None:
        return
    if not isinstance(section, list):
        raise ValueError(_UNSAFE_KUBECONFIG)
    for entry in section:
        if not isinstance(entry, dict) or not set(entry) <= {"name", entry_key}:
            raise ValueError(_UNSAFE_KUBECONFIG)
        if not isinstance(entry.get("name", ""), str):
            raise ValueError(_UNSAFE_KUBECONFIG)
        settings = entry.get(entry_key, {})
        if not isinstance(settings, dict) or not set(settings) <= allowed:
            raise ValueError(_UNSAFE_KUBECONFIG)
        if not all(_is_scalar_setting(key, value) for key, value in settings.items()):
            raise ValueError(_UNSAFE_KUBECONFIG)


def _reject_unsafe_kubeconfig(value: SecretStr) -> SecretStr:
    """Accept only inline kubeconfig settings that cannot run commands or read files."""
    text = value.get_secret_value()
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ValueError(_UNSAFE_KUBECONFIG)
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        raise ValueError("kubeconfig must be valid YAML") from None
    if (
        not isinstance(document, dict)
        or not set(document) <= _KUBECONFIG_TOP_LEVEL_KEYS
    ):
        raise ValueError(_UNSAFE_KUBECONFIG)
    for key in ("apiVersion", "kind", "current-context"):
        if key in document and not isinstance(document[key], str):
            raise ValueError(_UNSAFE_KUBECONFIG)
    if not isinstance(document.get("preferences", {}), dict):
        raise ValueError(_UNSAFE_KUBECONFIG)
    for section, (entry_key, allowed) in _KUBECONFIG_ENTRY_KEYS.items():
        _check_kubeconfig_entries(document.get(section), entry_key, allowed)
    return value


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
        if "\x00" in value:
            raise ValueError("AWS endpoint URL must not contain NUL characters")
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
    azure_provider: AzureCloudEnvironment

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

    @field_validator("kubernetes_kubeconfig", mode="after")
    @classmethod
    def validate_kubeconfig(cls, value: SecretStr) -> SecretStr:
        """Reject kubeconfigs that could execute plugins or reach host files."""
        return _reject_unsafe_kubeconfig(value)

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


@dataclass(frozen=True)
class ProviderInputIssue:
    """Value-free location and category of one rejected provider input."""

    location: tuple[str, ...]
    error_type: str


class ProviderInputError(ValueError):
    """Provider input rejection that never retains submitted values."""

    def __init__(self, issues: tuple[ProviderInputIssue, ...]) -> None:
        """Retain only the structural location and category of each issue."""
        self.issues = issues
        summary = ", ".join(
            f"{'.'.join(issue.location)}:{issue.error_type}" for issue in issues
        )
        super().__init__(f"Invalid provider input ({summary})")


def parse_provider_input(payload: object) -> ProviderInput:
    """Validate one provider payload, raising only value-free issues.

    Pydantic's structured errors keep rejected inputs even when they are hidden
    from the rendered message, so they never leave this boundary. The error is
    raised outside the handler so it does not chain the original exception.
    """
    try:
        return PROVIDER_INPUT_ADAPTER.validate_python(payload)
    except ValidationError as error:
        issues = tuple(
            ProviderInputIssue(
                tuple(str(part) for part in item["loc"]),
                item["type"],
            )
            for item in error.errors(
                include_url=False, include_context=False, include_input=False
            )
        )
    raise ProviderInputError(issues)
