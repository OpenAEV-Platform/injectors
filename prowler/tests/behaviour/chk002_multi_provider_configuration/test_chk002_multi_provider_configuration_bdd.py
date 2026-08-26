"""Behaviour tests for CHK.002 provider form input models."""

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import HttpUrl, SecretStr, TypeAdapter, ValidationError

from prowler.models.configs.config_loader import ConfigLoader, ProwlerConfig

PROVIDER_PAYLOADS: dict[str, dict[str, str]] = {
    "aws": {
        "provider": "aws",
        "aws_access_key_id": "EXAMPLEACCESSKEY",
        "aws_secret_access_key": "example-aws-secret",
        "aws_session_token": "example-aws-session-token",
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
    "aws": ("aws_secret_access_key", "aws_session_token"),
    "azure": ("azure_client_secret",),
    "gcp": ("gcp_service_account_json",),
    "kubernetes": ("kubernetes_kubeconfig",),
}

ORDINARY_FIELDS = {
    "aws": "aws_region",
    "azure": "azure_tenant_id",
    "gcp": "gcp_project_id",
    "kubernetes": "kubernetes_context",
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


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "kubernetes"])
def test_reject_mutation_of_provider_fields_without_leaking_secrets(
    provider: str,
) -> None:
    """Reject raw assignment before attempted credentials can enter an error."""
    payload = PROVIDER_PAYLOADS[provider]
    result = _when_submitted(payload)

    assert not isinstance(result, ValidationError)
    for field in (ORDINARY_FIELDS[provider], *SECRET_FIELDS[provider]):
        replacement_value = f"replacement-{provider}-secret"
        original_value = getattr(result, field)
        with pytest.raises(
            TypeError, match="^Provider inputs are immutable$"
        ) as raised:
            setattr(result, field, replacement_value)
        assert replacement_value not in str(raised.value)
        assert replacement_value not in repr(raised.value)
        assert all(
            payload[secret] not in str(raised.value)
            for secret in SECRET_FIELDS[provider]
        )
        assert all(
            payload[secret] not in repr(raised.value)
            for secret in SECRET_FIELDS[provider]
        )
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert getattr(result, field) == original_value


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "kubernetes"])
def test_deep_copy_preserves_secret_values_and_redaction(provider: str) -> None:
    """Deep-copy provider input without losing or exposing protected values."""
    payload = PROVIDER_PAYLOADS[provider]
    result = _when_submitted(payload)

    assert not isinstance(result, ValidationError)
    snapshot = result.model_copy(deep=True)
    assert snapshot is not result
    for field in SECRET_FIELDS[provider]:
        source_secret = getattr(result, field)
        copied_secret = getattr(snapshot, field)
        assert isinstance(source_secret, SecretStr)
        assert isinstance(copied_secret, SecretStr)
        assert copied_secret is not source_secret
        assert copied_secret.get_secret_value() == payload[field]
        assert payload[field] not in repr(snapshot)
        assert payload[field] not in str(snapshot)
        assert payload[field] not in json.dumps(snapshot.model_dump(mode="json"))
        for provider_input in (result, snapshot):
            attempted_value = f"deep-copy-replacement-{field}"
            with pytest.raises(
                TypeError, match="^Provider inputs are immutable$"
            ) as raised:
                setattr(provider_input, field, attempted_value)
            assert attempted_value not in str(raised.value)
            assert attempted_value not in repr(raised.value)
            assert getattr(provider_input, field).get_secret_value() == payload[field]


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

    assert set(type(config).model_fields) == {"openaev", "injector", "prowler"}
    assert not hasattr(config, "provider")
    assert not hasattr(config, "provider_config")
    assert not hasattr(config, "selected_provider_config")


def test_recommended_prowler_executable_path_is_default(
    standard_injector_environment: None,
    clean_prowler_environment: None,
) -> None:
    """Use the production Prowler executable location by default."""
    config = ConfigLoader()

    assert config.prowler.executable_path == Path("/usr/local/bin/prowler")


def test_absolute_prowler_executable_path_can_be_configured(
    standard_injector_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load a non-secret executable path from its environment setting."""
    configured_path = "/opt/prowler/bin/prowler"
    monkeypatch.setenv("PROWLER_EXECUTABLE_PATH", configured_path)

    config = ConfigLoader()

    assert config.prowler.executable_path == Path(configured_path)
    assert configured_path in config.model_dump_json()


def test_absolute_prowler_executable_path_can_be_loaded_from_yaml(
    standard_injector_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Load the executable path from the Prowler YAML runtime section."""
    configured_path = "/srv/prowler/bin/prowler"
    (tmp_path / "config.yml").write_text(
        f"prowler:\n  executable_path: '{configured_path}'\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(ConfigLoader.model_config, "yaml_file", None)

    config = ConfigLoader()

    assert config.prowler.executable_path == Path(configured_path)


@pytest.mark.parametrize("executable_path", ["", "   ", "bin/prowler"])
def test_reject_invalid_prowler_executable_path(
    standard_injector_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    executable_path: str,
) -> None:
    """Reject blank and relative executable paths at startup."""
    monkeypatch.setenv("PROWLER_EXECUTABLE_PATH", executable_path)

    with pytest.raises(ValidationError):
        ConfigLoader()


def test_aws_endpoint_url_defaults_to_none() -> None:
    """Use the AWS SDK service endpoint when an assessment supplies no override."""
    result = _when_submitted(PROVIDER_PAYLOADS["aws"])

    assert not isinstance(result, ValidationError)
    assert result.aws_endpoint_url is None


@pytest.mark.parametrize(
    "configured_url",
    [
        "https://s3.us-east-1.amazonaws.com",
        "http://localhost:4566",
        "http://localstack:4566",
        "http://10.0.0.25:4566",
        "https://aws.example.com:1/service/path",
        "https://aws.example.com:65535/service/path",
    ],
)
def test_trusted_aws_endpoint_url_can_be_supplied_per_assessment(
    configured_url: str,
) -> None:
    """Accept assessment-trusted HTTP endpoints without contacting their hosts."""
    result = _when_submitted(
        {**PROVIDER_PAYLOADS["aws"], "aws_endpoint_url": configured_url}
    )

    assert not isinstance(result, ValidationError)
    assert result.aws_endpoint_url == configured_url
    assert type(result.aws_endpoint_url) is str


def test_aws_endpoint_url_is_not_loaded_from_startup_environment(
    standard_injector_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep the per-assessment endpoint outside environment startup settings."""
    monkeypatch.setenv("PROWLER_AWS_ENDPOINT_URL", "http://localhost:4566")

    config = ConfigLoader()

    assert "aws_endpoint_url" not in ProwlerConfig.model_fields
    assert not hasattr(config.prowler, "aws_endpoint_url")


def test_aws_endpoint_url_is_not_loaded_from_startup_yaml(
    standard_injector_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep the per-assessment endpoint outside YAML startup settings."""
    (tmp_path / "config.yml").write_text(
        "prowler:\n  aws_endpoint_url: 'http://localhost:4566'\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(ConfigLoader.model_config, "yaml_file", None)

    config = ConfigLoader()

    assert "aws_endpoint_url" not in ProwlerConfig.model_fields
    assert not hasattr(config.prowler, "aws_endpoint_url")


@pytest.mark.parametrize(
    "configured_url",
    [
        b"https://aws.example.com/unchecked",
        HttpUrl("https://aws.example.com/service"),
        4566,
    ],
)
def test_reject_non_string_aws_endpoint_url(configured_url: object) -> None:
    """Reject endpoint values that could bypass checks through later coercion."""
    payload: dict[str, object] = {
        **PROVIDER_PAYLOADS["aws"],
        "aws_endpoint_url": configured_url,
    }

    with pytest.raises(ValidationError):
        _provider_input_adapter().validate_python(payload)


@pytest.mark.parametrize(
    "configured_url",
    [
        "",
        "   ",
        "/relative",
        "//localhost:4566",
        "https:///missing-host",
        "ftp://localhost:4566",
        "https://user:password@aws.example.com",
        "https://aws.example.com?region=local",
        "https://aws.example.com#credentials",
        "https://aws.example.com /service",
        "https://aws.example.com:\t4566",
        "https://aws.example.com:",
        "https://aws.example.com:abc",
        "https://aws.example.com:0",
        "https://aws.example.com:65536",
    ],
)
def test_reject_invalid_trusted_aws_endpoint_url(
    configured_url: str,
) -> None:
    """Reject endpoint overrides that cross the provider-input boundary."""
    payload = {**PROVIDER_PAYLOADS["aws"], "aws_endpoint_url": configured_url}

    with pytest.raises(ValidationError):
        _provider_input_adapter().validate_python(payload)


def test_aws_endpoint_url_samples_and_documentation_are_consistent() -> None:
    """Document the endpoint as provider input, never as a startup setting."""
    project_root = Path(__file__).parents[3]

    assert "PROWLER_AWS_ENDPOINT_URL" not in (project_root / ".env.sample").read_text(
        encoding="utf-8"
    )
    assert "aws_endpoint_url" not in (project_root / "config.yml.sample").read_text(
        encoding="utf-8"
    )
    readme = (project_root / "README.md").read_text(encoding="utf-8")
    assert "`PROWLER_AWS_ENDPOINT_URL`" not in readme
    assert "`prowler.aws_endpoint_url`" not in readme
    assert "`aws_endpoint_url`" in readme
    assert "per-assessment provider input" in readme


def test_runtime_path_samples_and_documentation_are_consistent() -> None:
    """Expose the same recommended runtime path in all operator guidance."""
    project_root = Path(__file__).parents[3]
    expected_path = "/usr/local/bin/prowler"

    assert f"PROWLER_EXECUTABLE_PATH={expected_path}" in (
        project_root / ".env.sample"
    ).read_text(encoding="utf-8")
    assert f"executable_path: '{expected_path}'" in (
        project_root / "config.yml.sample"
    ).read_text(encoding="utf-8")
    readme = (project_root / "README.md").read_text(encoding="utf-8")
    assert "`PROWLER_EXECUTABLE_PATH`" in readme
    assert "`prowler.executable_path`" in readme
    assert f"`{expected_path}`" in readme
