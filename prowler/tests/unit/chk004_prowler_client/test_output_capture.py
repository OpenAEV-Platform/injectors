"""Client-owned OCSF artifact capture tests for CHK.004."""

# ruff: noqa: D101, D102, D103

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AwsProviderInput


def _api() -> Any:
    from prowler._core import prowler_client

    return prowler_client


def _provider() -> AwsProviderInput:
    return AwsProviderInput(
        provider="aws",
        aws_access_key_id="AKIA_TEST",
        aws_secret_access_key=SecretStr("secret-canary"),
        aws_account_id="123456789012",
        aws_region="eu-west-1",
    )


def _result(
    *, return_code: int | None = 0, error: object | None = None
) -> CommandResult:
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
        stdout=b"\x1b[31mconsole-not-json\x1b[0m",
        stderr=b"console-stderr-canary",
        return_code=return_code,
        parsed=b"old-console-parser-value",
        error=error,
    )


@dataclass
class _Engine:
    result: CommandResult
    artifact: bytes = b'[{"finding":"artifact"}]'
    requests: list[Any] | None = None
    create_nested: bool = False
    failure: BaseException | None = None

    def run(self, request: Any) -> CommandResult:
        if self.requests is None:
            self.requests = []
        self.requests.append(request)
        directory = Path(
            request.arguments[request.arguments.index("--output-directory") + 1]
        )
        (directory / "findings.ocsf.json").write_bytes(self.artifact)
        if self.create_nested:
            nested = directory / "compliance" / "provider"
            nested.mkdir(parents=True)
            (nested / "summary.csv").write_text("fixture", encoding="utf-8")
        if self.failure is not None:
            raise self.failure
        return self.result


@dataclass(frozen=True)
class _EngineFactory:
    engine: _Engine

    def create(self) -> _Engine:
        return self.engine


@dataclass
class _CleanupReportingWorkspace:
    wrapped: Any

    @property
    def directory(self) -> Path:
        return cast(Path, self.wrapped.directory)

    @property
    def backend(self) -> str:
        return cast(str, self.wrapped.backend)

    def read_artifact(self, *, maximum_bytes: int) -> bytes:
        return cast(bytes, self.wrapped.read_artifact(maximum_bytes=maximum_bytes))

    def cleanup(self) -> None:
        self.wrapped.cleanup()
        raise OSError("unsafe cleanup path canary")


@dataclass(frozen=True)
class _CleanupReportingWorkspaceFactory:
    wrapped: Any

    def create(self) -> _CleanupReportingWorkspace:
        return _CleanupReportingWorkspace(self.wrapped.create())


def _factory(engine: _Engine, tmp_path: Path, **kwargs: Any) -> Any:
    return _api().ProwlerClientFactory(
        engine_factory=_EngineFactory(engine),
        output_workspace_factory=_api().TemporaryOutputWorkspaceFactory(
            platform_name="nt", temporary_root=tmp_path
        ),
        **kwargs,
    )


def test_success_uses_artifact_but_preserves_console_and_process_result(
    tmp_path: Path,
) -> None:
    original = _result()
    engine = _Engine(original, create_nested=True)

    captured = _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )

    assert captured is not original
    assert captured.specification is original.specification
    assert captured.stdout == original.stdout
    assert captured.stderr == original.stderr
    assert captured.return_code == original.return_code
    assert captured.error is original.error
    assert captured.parsed == engine.artifact
    assert engine.requests is not None
    assert not Path(
        engine.requests[0].arguments[
            engine.requests[0].arguments.index("--output-directory") + 1
        ]
    ).exists()


@pytest.mark.parametrize(
    ("return_code", "error"),
    [(3, None), (7, None), (0, "engine-error")],
)
def test_engine_failure_result_is_unchanged_and_ignores_partial_artifact(
    tmp_path: Path, return_code: int, error: object | None
) -> None:
    original = _result(return_code=return_code, error=error)
    engine = _Engine(original, artifact=b"partial-invalid-artifact")

    captured = _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )

    assert captured is original


def test_missing_success_artifact_raises_typed_error_and_cleans_workspace(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    caplog.set_level(logging.ERROR)
    engine = _Engine(_result())

    def no_artifact(request: Any) -> CommandResult:
        if engine.requests is None:
            engine.requests = []
        engine.requests.append(request)
        return engine.result

    engine.run = no_artifact  # type: ignore[method-assign]
    with pytest.raises(_api().OutputArtifactError) as caught:
        _factory(engine, tmp_path).run(
            ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
        )
    assert caught.value.kind == "missing"
    assert engine.requests is not None
    workspace_path = Path(
        engine.requests[0].arguments[
            engine.requests[0].arguments.index("--output-directory") + 1
        ]
    )
    assert not workspace_path.exists()
    assert [record.getMessage() for record in caplog.records] == [
        "Prowler output artifact capture failed"
    ]
    assert caplog.records[0].levelno == logging.ERROR


def test_request_has_small_console_limit_and_exact_ordered_output_controls(
    tmp_path: Path,
) -> None:
    engine = _Engine(_result())
    _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )
    assert engine.requests is not None
    request = engine.requests[0]
    arguments = request.arguments
    output_index = arguments.index("--output-directory")

    assert request.maximum_accepted_output_bytes == 4 * 1024 * 1024
    assert arguments[:output_index] == (
        "aws",
        "--region",
        "eu-west-1",
        "--severity",
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    )
    assert arguments[output_index + 2 :] == (
        "--output-filename",
        "findings",
        "-z",
        "--only-logs",
        "--no-color",
        "-M",
        "json-ocsf",
    )
    assert arguments[-2:] == ("-M", "json-ocsf")
    assert "-z" in arguments
    assert "--ignore-exit-code-3" not in arguments


@pytest.mark.parametrize(
    "selector_arguments",
    [("-c", "check"), ("--services", "s3"), ("--compliance", "cis_3.0_aws")],
)
def test_narrowed_runs_do_not_receive_all_severity_override(
    tmp_path: Path, selector_arguments: tuple[str, str]
) -> None:
    class Adapter:
        def adapt(self, _provider: AwsProviderInput) -> Any:
            return SimpleNamespace(
                arguments=("aws", *selector_arguments),
                environment=(),
                credential_leases=(),
            )

    engine = _Engine(_result())
    workspace_factory = _api().TemporaryOutputWorkspaceFactory(
        platform_name="nt", temporary_root=tmp_path
    )
    client = _api().ProwlerClient(
        config=ProwlerConfig(executable_path="/opt/prowler/bin/prowler"),
        provider=_provider(),
        engine=engine,
        provider_adapter=cast(Any, Adapter()),
        output_workspace_factory=workspace_factory,
    )

    client.run()
    assert engine.requests is not None
    assert "--severity" not in engine.requests[0].arguments


def test_logs_are_fixed_phased_and_exclude_sensitive_canaries(
    caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    caplog.set_level(logging.DEBUG)
    engine = _Engine(_result(), artifact=b'[{"secret":"artifact-canary"}]')

    _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )

    messages = [record.getMessage() for record in caplog.records]
    assert {
        "Preparing Prowler output workspace",
        "Prowler process completed",
        "Prowler output artifact captured",
        "Prowler output workspace cleaned",
    }.issubset(messages)
    rendered = "\n".join(
        f"{record.levelname} {record.getMessage()} {record.__dict__}"
        for record in caplog.records
    )
    assert "secret-canary" not in rendered
    assert "artifact-canary" not in rendered
    assert "console-stderr-canary" not in rendered
    assert str(tmp_path) not in rendered
    assert any(record.levelno == logging.DEBUG for record in caplog.records)
    artifact_metadata = next(
        cast(Any, record).prowler_metadata
        for record in caplog.records
        if record.getMessage() == "Prowler output artifact metadata"
    )
    assert artifact_metadata == {"artifact_bytes": len(engine.artifact)}


def test_logging_failure_cannot_change_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    engine = _Engine(_result())
    monkeypatch.setattr(
        "prowler._core.prowler_client.client._LOGGER.log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("logger failed")),
    )

    captured = _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )
    assert captured.parsed == engine.artifact


@pytest.mark.parametrize("failure_type", [MemoryError, RecursionError])
def test_debug_logging_never_decodes_artifact_or_changes_success(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure_type: type[BaseException],
) -> None:
    caplog.set_level(logging.DEBUG)
    engine = _Engine(_result())
    decode_calls = 0

    def fail_if_decoded(_payload: object, *_args: object, **_kwargs: object) -> object:
        nonlocal decode_calls
        decode_calls += 1
        raise failure_type("debug decoding must not run")

    monkeypatch.setattr(json, "loads", fail_if_decoded)

    captured = _factory(engine, tmp_path).run(
        ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
    )

    assert captured.parsed == engine.artifact
    assert decode_calls == 0
    artifact_metadata = next(
        cast(Any, record).prowler_metadata
        for record in caplog.records
        if record.getMessage() == "Prowler output artifact metadata"
    )
    assert artifact_metadata == {"artifact_bytes": len(engine.artifact)}


def test_cleanup_failure_after_success_surfaces_only_safe_cleanup_error(
    tmp_path: Path,
) -> None:
    engine = _Engine(_result())
    normal_factory = _api().TemporaryOutputWorkspaceFactory(
        platform_name="nt", temporary_root=tmp_path
    )
    factory = _api().ProwlerClientFactory(
        engine_factory=_EngineFactory(engine),
        output_workspace_factory=_CleanupReportingWorkspaceFactory(normal_factory),
    )

    with pytest.raises(_api().OutputWorkspaceCleanupError) as caught:
        factory.run(
            ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
        )

    assert str(caught.value) == "temporary output workspace cleanup failed"
    assert "canary" not in repr(caught.value)


@pytest.mark.parametrize("primary_kind", ["exception", "result"])
def test_cleanup_failure_never_masks_primary_and_emits_safe_warning(
    caplog: pytest.LogCaptureFixture, tmp_path: Path, primary_kind: str
) -> None:
    caplog.set_level(logging.WARNING)
    primary = RuntimeError("safe primary failure")
    result = _result(return_code=7) if primary_kind == "result" else _result()
    engine = _Engine(result, failure=primary if primary_kind == "exception" else None)
    normal_factory = _api().TemporaryOutputWorkspaceFactory(
        platform_name="nt", temporary_root=tmp_path
    )
    factory = _api().ProwlerClientFactory(
        engine_factory=_EngineFactory(engine),
        output_workspace_factory=_CleanupReportingWorkspaceFactory(normal_factory),
    )

    if primary_kind == "exception":
        with pytest.raises(RuntimeError) as caught:
            factory.run(
                ProwlerConfig(executable_path="/opt/prowler/bin/prowler"),
                _provider(),
            )
        assert caught.value is primary
        assert caught.value.__notes__ == [
            "temporary output workspace cleanup also failed"
        ]
    else:
        captured = factory.run(
            ProwlerConfig(executable_path="/opt/prowler/bin/prowler"), _provider()
        )
        assert captured is result

    warnings = [
        record for record in caplog.records if record.levelno == logging.WARNING
    ]
    assert [record.getMessage() for record in warnings] == [
        "Secondary Prowler output cleanup failure"
    ]
    assert "canary" not in "\n".join(str(record.__dict__) for record in warnings)
