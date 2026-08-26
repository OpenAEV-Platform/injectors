"""Behaviour tests for CHK.002 provider form input models."""

import importlib
import json
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from prowler.models.configs.config_loader import ConfigLoader

PROVIDER_PAYLOADS: dict[str, dict[str, str]] = {
    "aws": {
        "provider": "aws",
        "aws_access_key_id": "EXAMPLEACCESSKEY",
        "aws_secret_access_key": "example-aws-secret",
        "aws_account_id": "123456789012",
        "aws_region": "eu-west-1",
    },
    "azure": {
        "provider": "azure",
        "azure_tenant_id": "example-tenant",
        "azure_client_id": "example-client",
        "azure_client_secret": "example-azure-secret",
        "azure_subscription_id": "example-subscription",
        "azure_provider": "Microsoft.Compute",
    },
    "gcp": {
        "provider": "gcp",
        "gcp_service_account_json": (
            '{"type":"service_account","private_key":"example-gcp-secret"}'
        ),
        "gcp_project_id": "example-project",
    },
    "kubernetes": {
        "provider": "kubernetes",
        "kubernetes_kubeconfig": (
            "apiVersion: v1\nusers: []\n# example-kubernetes-secret"
        ),
        "kubernetes_context": "example-context",
    },
}

SECRET_FIELDS = {
    "aws": ("aws_secret_access_key",),
    "azure": ("azure_client_secret",),
    "gcp": ("gcp_service_account_json",),
    "kubernetes": ("kubernetes_kubeconfig",),
}


def _provider_input_adapter() -> TypeAdapter[Any]:
    try:
        module = importlib.import_module("prowler.models.provider_inputs")
    except ModuleNotFoundError:
        pytest.fail("reusable provider input models are absent")
    return module.PROVIDER_INPUT_ADAPTER  # type: ignore[no-any-return]


def _when_submitted(payload: dict[str, str]) -> Any | ValidationError:
    try:
        return _provider_input_adapter().validate_python(payload)
    except ValidationError as error:
        return error


def _ordinary_outputs(provider_input: Any) -> tuple[str, str, str]:
    json_dump = provider_input.model_dump(mode="json")
    return repr(provider_input), str(provider_input), json.dumps(json_dump)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "kubernetes"])
def test_select_exactly_one_supported_provider(provider: str) -> None:
    """Accept each supported discriminator as exactly one provider model."""
    result = _when_submitted(PROVIDER_PAYLOADS[provider])

    assert not isinstance(result, ValidationError)
    assert result.provider == provider
    assert type(result).__name__.lower().startswith(provider)


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "kubernetes"])
def test_protect_credentials_from_ordinary_output(provider: str) -> None:
    """Redact provider credentials from repr, str, and JSON-mode dumps."""
    payload = PROVIDER_PAYLOADS[provider]
    result = _when_submitted(payload)

    assert not isinstance(result, ValidationError)
    outputs = _ordinary_outputs(result)
    for field in SECRET_FIELDS[provider]:
        assert all(payload[field] not in output for output in outputs)
    assert all("**********" in output for output in outputs)


def test_protect_optional_aws_session_token() -> None:
    """Accept and redact the optional nonblank AWS session token."""
    submitted_value = "example-aws-session-token"
    result = _when_submitted(
        {**PROVIDER_PAYLOADS["aws"], "aws_session_token": submitted_value}
    )

    assert not isinstance(result, ValidationError)
    assert all(submitted_value not in output for output in _ordinary_outputs(result))


def test_reject_missing_provider_selection() -> None:
    """Reject form input without its provider discriminator."""
    result = _when_submitted({})

    assert isinstance(result, ValidationError)


def test_reject_unknown_provider_without_leaking_input() -> None:
    """Reject an unknown discriminator without echoing submitted values."""
    submitted_value = "example-unknown-secret"
    result = _when_submitted({"provider": "oracle", "credential": submitted_value})

    assert isinstance(result, ValidationError)
    assert submitted_value not in str(result)


def test_reject_cross_provider_field_without_leaking_it() -> None:
    """Forbid extra cross-provider fields without echoing their values."""
    submitted_value = "example-cross-provider-secret"
    payload = {**PROVIDER_PAYLOADS["aws"], "azure_client_secret": submitted_value}

    result = _when_submitted(payload)

    assert isinstance(result, ValidationError)
    assert "azure_client_secret" in str(result)
    assert submitted_value not in str(result)


@pytest.mark.parametrize("provider", ["AWS", " aws "])
def test_provider_discriminator_is_strict(provider: str) -> None:
    """Reject discriminator values whose case or whitespace is altered."""
    payload = {**PROVIDER_PAYLOADS["aws"], "provider": provider}

    result = _when_submitted(payload)

    assert isinstance(result, ValidationError)


@pytest.mark.parametrize(
    ("provider", "field"),
    [
        ("aws", "aws_secret_access_key"),
        ("azure", "azure_client_secret"),
        ("gcp", "gcp_service_account_json"),
        ("kubernetes", "kubernetes_kubeconfig"),
    ],
)
def test_reject_blank_required_values_without_leaking_them(
    provider: str,
    field: str,
) -> None:
    """Reject blank required values without including input in errors."""
    payload = {**PROVIDER_PAYLOADS[provider], field: " \t "}

    result = _when_submitted(payload)

    assert isinstance(result, ValidationError)
    assert field in str(result)
    assert "input_value" not in str(result)


def test_startup_configuration_remains_provider_free(
    standard_injector_environment: None,
) -> None:
    """Keep provider form input outside the six-setting startup boundary."""
    config = ConfigLoader()

    assert set(type(config).model_fields) == {"openaev", "injector"}
    assert not hasattr(config, "provider")
    assert not hasattr(config, "provider_config")
    assert not hasattr(config, "selected_provider_config")
