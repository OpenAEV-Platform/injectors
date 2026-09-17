"""Executable behaviour contract for CHK.004."""

# ruff: noqa: D103

import importlib
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
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


def _failed_result() -> CommandResult:
    return CommandResult(
        specification=ExecutionSpecification(
            executable="/opt/prowler/bin/prowler",
            arguments=(),
            environment=(),
            working_directory=None,
            input_bytes=b"",
            output=OutputSpecification(parser="raw"),
            timeout_seconds=1,
            maximum_accepted_output_bytes=1,
        ),
        return_code=1,
        error="safe engine error",
    )


def test_create_does_not_execute(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    factory = _factory(recording_engine)

    client = factory.create(_config(), provider_inputs["AWS"])

    assert client is not None
    assert recording_engine.requests == []


def test_full_assessment_preserves_result_and_captures_artifact_without_check_selector(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])

    result = client.run()

    assert recording_engine.result is not None
    assert result is not recording_engine.result
    assert isinstance(result, CommandResult)
    assert result.stdout == recording_engine.result.stdout
    assert result.stderr == recording_engine.result.stderr
    assert result.return_code == recording_engine.result.return_code
    assert result.specification == recording_engine.result.specification
    assert result.parsed == recording_engine.artifact_bytes
    assert "-c" not in recording_engine.requests[0].arguments


def test_factory_run_matches_created_client_request(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    factory = _factory(recording_engine)

    direct = factory.create(_config(), provider_inputs["AWS"]).run(("one", "two"))
    quick = factory.run(_config(), provider_inputs["AWS"], check_filters=("one", "two"))

    assert direct.parsed == quick.parsed == recording_engine.artifact_bytes
    first = recording_engine.requests[0]
    second = recording_engine.requests[1]
    first_arguments = list(first.arguments)
    second_arguments = list(second.arguments)
    first_arguments[first_arguments.index("--output-directory") + 1] = "<workspace>"
    second_arguments[second_arguments.index("--output-directory") + 1] = "<workspace>"
    assert tuple(first_arguments) == tuple(second_arguments)
    assert first.environment == second.environment


def test_check_filters_are_separate_ordered_tokens(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])

    client.run(("check-z", "check-a", "check-z"))

    arguments = recording_engine.requests[0].arguments
    selector_index = arguments.index("-c")
    assert arguments[selector_index : selector_index + 4] == (
        "-c",
        "check-z",
        "check-a",
        "check-z",
    )
    assert selector_index < arguments.index("--output-directory")


@pytest.mark.parametrize(
    ("provider_name", "expected_arguments", "expected_environment"),
    [
        (
            "AWS",
            ("aws", "--region", "eu-west-1"),
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
            ),
            set(),
        ),
        (
            "Kubernetes",
            (
                "kubernetes",
                "--kubeconfig-file",
                "<temporary>",
                "--context",
                "cluster-context",
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
        (
            "<temporary>"
            if index in {2} and provider_name in {"GCP", "Kubernetes"}
            else item
        )
        for index, item in enumerate(request.arguments)
    )
    assert arguments[: len(expected_arguments)] == expected_arguments
    assert arguments[-2:] == ("-M", "json-ocsf")
    assert set(_environment(request)) == expected_environment
    assert all(isinstance(value, SecretStr) for value in _environment(request).values())
    rendered = repr(request.arguments)
    assert all(
        secret not in rendered
        for secret in ("aws-secret", "azure-secret", "gcp-secret", "kube-secret")
    )


def test_configured_aws_endpoint_is_a_plain_aws_only_environment_value(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    endpoint = "https://aws.internal.example:8443"
    provider = provider_inputs["AWS"].model_copy(update={"aws_endpoint_url": endpoint})

    _factory(recording_engine).run(_config(), provider)

    request = recording_engine.requests[0]
    assert _environment(request) == {
        "AWS_ACCESS_KEY_ID": SecretStr("AKIA_TEST"),
        "AWS_SECRET_ACCESS_KEY": SecretStr("aws-secret"),
        "AWS_SESSION_TOKEN": SecretStr("aws-session"),
        "AWS_ENDPOINT_URL": endpoint,
    }
    assert isinstance(_environment(request)["AWS_ENDPOINT_URL"], str)
    assert endpoint not in request.arguments


def test_unset_aws_endpoint_preserves_exact_aws_environment(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    _factory(recording_engine).run(_config(), provider_inputs["AWS"])

    request = recording_engine.requests[0]
    assert _environment(request) == {
        "AWS_ACCESS_KEY_ID": SecretStr("AKIA_TEST"),
        "AWS_SECRET_ACCESS_KEY": SecretStr("aws-secret"),
        "AWS_SESSION_TOKEN": SecretStr("aws-session"),
    }
    assert "AWS_ENDPOINT_URL" not in request.arguments


def test_unset_aws_endpoint_ignores_ambient_value_without_session_token(
    monkeypatch: pytest.MonkeyPatch,
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
) -> None:
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://ambient.example.invalid")
    provider = provider_inputs["AWS"].model_copy(update={"aws_session_token": None})

    _factory(recording_engine).run(_config(), provider)

    request = recording_engine.requests[0]
    assert _environment(request) == {
        "AWS_ACCESS_KEY_ID": SecretStr("AKIA_TEST"),
        "AWS_SECRET_ACCESS_KEY": SecretStr("aws-secret"),
    }
    assert "AWS_ENDPOINT_URL" not in request.arguments


def test_kubernetes_uses_prowler_536_context_flag_not_stale_alias(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    _factory(recording_engine).run(_config(), provider_inputs["Kubernetes"])

    arguments = recording_engine.requests[0].arguments
    assert "--context" in arguments
    assert arguments[arguments.index("--context") + 1] == "cluster-context"
    assert "--kube-context" not in arguments


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
def test_temporary_credentials_are_private_unique_and_always_removed(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    provider_name: str,
    outcome: str,
) -> None:
    if outcome == "result_error":
        recording_engine.result = _failed_result()
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
    assert recording_engine.observed_directory_modes == [0o700]
    assert recording_engine.observed_contents
    assert not path.exists()
    assert not path.parent.exists()
    expected_suffix = ".json" if provider_name == "GCP" else ".yaml"
    assert path.suffix == expected_suffix
    assert recording_engine.observed_contents[0] not in repr(request.arguments)


def test_each_file_backed_run_uses_a_unique_private_directory(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    factory = _factory(recording_engine)

    factory.run(_config(), provider_inputs["GCP"])
    factory.run(_config(), provider_inputs["GCP"])

    paths = [Path(request.arguments[2]) for request in recording_engine.requests]
    assert paths[0].parent != paths[1].parent
    assert all(not path.parent.exists() for path in paths)


def test_windows_lease_uses_temp_acl_without_posix_permission_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = _api()
    chmod_calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        os,
        "chmod",
        lambda path, mode: chmod_calls.append((path, mode)),
    )
    factory = api.TemporaryCredentialLeaseFactory(
        platform_name="nt", temporary_root=tmp_path
    )

    lease = factory.create(SecretStr("credential"), suffix=".json")
    try:
        assert lease.path.read_text(encoding="utf-8") == "credential"
        assert chmod_calls == []
    finally:
        lease.cleanup()


def test_credential_file_is_closed_before_engine_execution(
    recording_engine: RecordingEngine, provider_inputs: dict[str, Any]
) -> None:
    _factory(recording_engine).run(_config(), provider_inputs["Kubernetes"])

    # Reading in RecordingEngine proves the writer released its handle before run().
    assert recording_engine.observed_contents == ["kube-secret"]


def test_credential_lease_cleanup_is_idempotent(tmp_path: Path) -> None:
    factory_class = _api().TemporaryCredentialLeaseFactory
    lease = factory_class(temporary_root=tmp_path).create(
        SecretStr("credential"), suffix=".json"
    )

    lease.cleanup()
    lease.cleanup()

    assert not lease.path.exists()
    assert not lease.directory.exists()


def test_creation_write_failure_removes_partial_file_and_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    factory_class = _api().TemporaryCredentialLeaseFactory
    original_fdopen = os.fdopen

    class PartialWriteFailure:
        def __init__(self, descriptor: int, *args: Any, **kwargs: Any) -> None:
            self.wrapped = original_fdopen(descriptor, *args, **kwargs)

        def __enter__(self) -> "PartialWriteFailure":
            return self

        def write(self, content: str) -> None:
            self.wrapped.write(content[:1])
            self.wrapped.flush()
            raise OSError("safe write failure")

        def __exit__(self, *_args: Any) -> None:
            self.wrapped.close()

    monkeypatch.setattr(os, "fdopen", PartialWriteFailure)

    with pytest.raises(OSError, match="safe write failure"):
        factory_class(temporary_root=tmp_path).create(
            SecretStr("credential"), suffix=".json"
        )

    assert list(tmp_path.iterdir()) == []


class _FailingCleanupLease:
    def __init__(self, path: Path) -> None:
        self.path = path

    def cleanup(self) -> None:
        raise OSError("cleanup failure without path")


class _FailingCleanupFactory:
    def __init__(self, path: Path) -> None:
        self.path = path

    def create(self, _content: SecretStr, *, suffix: str) -> _FailingCleanupLease:
        assert suffix in {".json", ".yaml"}
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_text("non-secret fixture", encoding="utf-8")
        return _FailingCleanupLease(self.path)


def test_cleanup_failure_after_success_raises_safe_cleanup_error(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    tmp_path: Path,
) -> None:
    api = _api()
    factory = api.ProwlerClientFactory(
        engine_factory=RecordingEngineFactory(recording_engine),
        credential_lease_factory=_FailingCleanupFactory(tmp_path / "credential.json"),
    )

    with pytest.raises(api.CredentialCleanupError) as caught:
        factory.run(_config(), provider_inputs["GCP"])

    rendered = repr(caught.value)
    assert "credential.json" not in rendered
    assert "gcp-secret" not in rendered


def test_cleanup_failure_preserves_primary_exception_with_safe_note(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    tmp_path: Path,
) -> None:
    api = _api()
    primary = RuntimeError("safe primary execution failure")
    recording_engine.raised = primary
    factory = api.ProwlerClientFactory(
        engine_factory=RecordingEngineFactory(recording_engine),
        credential_lease_factory=_FailingCleanupFactory(tmp_path / "credential.yaml"),
    )

    with pytest.raises(RuntimeError) as caught:
        factory.run(_config(), provider_inputs["Kubernetes"])

    assert caught.value is primary
    assert caught.value.__notes__ == ["temporary credential cleanup also failed"]
    assert "credential.yaml" not in repr(caught.value)
    assert "kube-secret" not in repr(caught.value)


@pytest.mark.parametrize("terminal", ["success", "invalid_filter", "engine_error"])
def test_client_releases_provider_and_rejects_second_run(
    recording_engine: RecordingEngine,
    provider_inputs: dict[str, Any],
    terminal: str,
) -> None:
    api = _api()
    client = _factory(recording_engine).create(_config(), provider_inputs["AWS"])
    if terminal == "engine_error":
        recording_engine.raised = RuntimeError("safe engine error")

    try:
        client.run(("",) if terminal == "invalid_filter" else ())
    except (RuntimeError, ValueError):
        pass

    assert client._provider is None
    with pytest.raises(api.ProwlerClientConsumedError, match="already been consumed"):
        client.run()
    assert "aws-secret" not in repr(client)


def test_readme_discloses_plaintext_runtime_and_residual_risk() -> None:
    readme = (Path(__file__).parents[3] / "README.md").read_text(encoding="utf-8")
    required_phrases = (
        "plaintext",
        "command runtime",
        "deleted in `finally`",
        "crash",
        "power loss",
        "ephemeral storage",
        "Windows",
        "ACL",
        "encrypt",
        "stale",
        "zeroiz",
    )

    assert all(phrase.lower() in readme.lower() for phrase in required_phrases)
