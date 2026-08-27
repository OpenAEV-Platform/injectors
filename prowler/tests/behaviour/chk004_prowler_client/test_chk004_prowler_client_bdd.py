"""Executable behaviour contract for CHK.004."""

# ruff: noqa: D103

import importlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import CommandResult
from prowler.models.configs.config_loader import ProwlerConfig

from .conftest import RecordingEngine, RecordingEngineFactory


def _api() -> Any:
    try:
        return importlib.import_module("prowler._core.prowler_client")
    except ModuleNotFoundError:
        return importlib.import_module("prowler._core.client")


def _factory(engine: RecordingEngine) -> Any:
    return _api().ProwlerClientFactory(engine_factory=RecordingEngineFactory(engine))


def _config() -> ProwlerConfig:
    return ProwlerConfig(executable_path="/opt/prowler/bin/prowler")


def _environment(request: Any) -> dict[str, Any]:
    return dict(request.environment)


def test_create_does_not_execute(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    factory = _factory(recording_engine)

    client = factory.create(_config(), provider_inputs["AWS"])

    assert client is not None
    assert recording_engine.requests == []


def test_full_assessment_returns_exact_result_without_check_selector(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])

    result = client.run()

    assert result is recording_engine.result
    assert isinstance(result, CommandResult)
    assert "-c" not in recording_engine.requests[0].arguments


def test_factory_run_matches_created_client_request(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    factory = _factory(recording_engine)

    direct = factory.create(_config(), provider_inputs["AWS"]).run(("one", "two"))
    quick = factory.run(_config(), provider_inputs["AWS"], check_filters=("one", "two"))

    assert direct is quick
    assert recording_engine.requests[0] == recording_engine.requests[1]


def test_check_filters_are_separate_ordered_tokens(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])

    client.run(("check-z", "check-a", "check-z"))

    arguments = recording_engine.requests[0].arguments
    assert arguments[-4:] == ("-c", "check-z", "check-a", "check-z")


@pytest.mark.parametrize(
    ("provider_name", "expected_arguments", "expected_environment"),
    [
        (
            "AWS",
            ("aws", "--region", "eu-west-1", "-M", "json-ocsf"),
            {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"},
        ),
        (
            "Azure",
            (
                "azure",
                "--sp-env-auth",
                "--subscription-id",
                "subscription-id",
                "--azure-region",
                "AzureUSGovernment",
                "-M",
                "json-ocsf",
            ),
            {"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"},
        ),
        (
            "GCP",
            (
                "gcp",
                "--credentials-file",
                "<temporary>",
                "--project-id",
                "project-id",
                "-M",
                "json-ocsf",
            ),
            set(),
        ),
        (
            "Kubernetes",
            (
                "kubernetes",
                "--kubeconfig-file",
                "<temporary>",
                "--kube-context",
                "cluster-context",
                "-M",
                "json-ocsf",
            ),
            set(),
        ),
    ],
)
def test_provider_invocation_is_explicit_and_secret_safe(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    provider_name: str,
    expected_arguments: tuple[str, ...],
    expected_environment: set[str],
) -> None:
    _factory(recording_engine).run(_config(), provider_inputs[provider_name])

    request = recording_engine.requests[0]
    arguments = tuple(
        "<temporary>" if index in {2} and provider_name in {"GCP", "Kubernetes"} else item
        for index, item in enumerate(request.arguments)
    )
    assert arguments == expected_arguments
    assert set(_environment(request)) == expected_environment
    assert all(
        isinstance(value, SecretStr) for value in _environment(request).values()
    )
    rendered = repr(request.arguments)
    assert all(secret not in rendered for secret in ("aws-secret", "azure-secret", "gcp-secret", "kube-secret"))


@pytest.mark.parametrize("filters", [("",), ("  ",), ("ok", "\t")])
def test_blank_filters_are_rejected_without_execution(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    filters: tuple[str, ...],
) -> None:
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])

    with pytest.raises(ValueError, match="check filters must be nonblank strings"):
        client.run(filters)

    assert recording_engine.requests == []


def test_request_uses_exact_bounded_raw_execution_contract(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    _factory(recording_engine).run(_config(), provider_inputs["AWS"])

    request = recording_engine.requests[0]
    assert request.executable == "/opt/prowler/bin/prowler"
    assert request.output.parser == "raw"
    assert request.input_bytes == b""
    assert request.working_directory is None
    assert request.timeout_seconds == _api().DEFAULT_TIMEOUT_SECONDS
    assert (
        request.maximum_accepted_output_bytes
        == _api().DEFAULT_MAXIMUM_ACCEPTED_OUTPUT_BYTES
    )


@pytest.mark.parametrize("provider_name", ["GCP", "Kubernetes"])
@pytest.mark.parametrize("outcome", ["success", "result_error", "exception"])
def test_temporary_credentials_are_owner_only_and_always_removed(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    provider_name: str,
    outcome: str,
) -> None:
    if outcome == "result_error":
        recording_engine.result = object()
    elif outcome == "exception":
        recording_engine.raised = RuntimeError("safe execution failure")
    factory = _factory(recording_engine)

    try:
        factory.run(_config(), provider_inputs[provider_name])
    except RuntimeError as error:
        assert "secret" not in repr(error)

    request = recording_engine.requests[0]
    path = Path(request.arguments[2])
    assert recording_engine.observed_modes == [0o600]
    assert recording_engine.observed_contents
    assert not path.exists()
    assert recording_engine.observed_contents[0] not in repr(request.arguments)
