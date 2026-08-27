"""Raw pytest executable contract for CHK.007."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from pydantic import SecretStr
from pyoaev.configuration import ConfigLoaderOAEV

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    ValidatedCommandRequest,
)
from prowler._core.prowler_client import (
    OUTPUT_ARTIFACT_FILENAME,
    ProwlerClientFactory,
)
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, stable_contract_id
from prowler.models.configs.config_loader import (
    ConfigLoader,
    InjectorConfig,
    ProwlerConfig,
)
from prowler.models.findings import OpenAevFinding

from .conftest import RecordingLogger

_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"


def _contract() -> Any:
    try:
        return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("aws")))
    except LookupError:
        pytest.fail("CHK.007 AWS base contract is not registered")


def _config() -> ConfigLoader:
    return ConfigLoader.model_construct(
        openaev=ConfigLoaderOAEV(
            url="http://127.0.0.1:8080", token="runtime-placeholder"
        ),
        injector=InjectorConfig(id="injector-test"),
        prowler=ProwlerConfig(executable_path="/fake/prowler"),
    )


def _specification(arguments: tuple[str, ...] = ()) -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=arguments,
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=__import__(
            "prowler._core.cli_engine", fromlist=["OutputSpecification"]
        ).OutputSpecification(parser="raw"),
        timeout_seconds=1.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _ClientFactory:
    result: CommandResult
    calls: list[tuple[Any, Any, tuple[str, ...]]] = field(default_factory=list)

    def run(
        self, config: Any, provider: Any, *, check_filters: Any = ()
    ) -> CommandResult:
        self.calls.append((config, provider, tuple(check_filters)))
        return self.result


def test_default_registration_identity_fields_and_outputs() -> None:
    """The canonical AWS base route remains first in the executable surface."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    expected_id = stable_contract_id("aws")

    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id("aws")),
        str(stable_contract_id("azure")),
        str(stable_contract_id("gcp")),
        str(stable_contract_id("kubernetes")),
    ]
    assert UUID(serialized[0]["contract_id"]) == expected_id
    assert expected_id.version == 5
    content = json.loads(serialized[0]["contract_content"])
    assert content["external_id"] == "prowler:aws"
    assert tuple(field["key"] for field in content["fields"]) == (
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_account_id",
        "aws_region",
        "aws_endpoint_url",
        "aws_session_token",
    )
    assert tuple(output["field"] for output in content["outputs"]) == (
        "findings",
        "vulnerabilities",
    )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("aws_access_key_id", " "),
        ("aws_secret_access_key", ""),
        ("aws_session_token", "\t"),
        ("aws_account_id", "12345678901"),
        ("aws_account_id", "12345678901x"),
        ("aws_region", " "),
    ),
)
def test_invalid_input_is_rejected_before_dispatch(
    aws_form: dict[str, object], field_name: str, invalid_value: str
) -> None:
    """All credential and target validation remains local and pre-dispatch."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract()
    contract._client_factory = factory
    raw = {**aws_form, field_name: invalid_value}

    with pytest.raises(ValueError):
        contract.parse_input(raw)

    assert factory.calls == []


def test_aws_account_id_rejects_unicode_numerals(
    aws_form: dict[str, object],
) -> None:
    """An AWS account ID must contain exactly 12 ASCII digits."""
    contract = _contract()

    with pytest.raises(ValueError):
        contract.parse_input({**aws_form, "aws_account_id": "１２３４５６７８９０１２"})


def test_valid_request_invokes_client_once_without_narrowing(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """The concrete base route passes the complete AWS scope once."""
    artifact = json.dumps([ocsf_record_factory("one")]).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory

    outcome = contract.execute(ProwlerConfig(), contract.parse_input(aws_form))

    assert len(factory.calls) == 1
    assert factory.calls[0][2] == ()
    assert len(outcome.findings) == 1
    assert outcome.raw_record_count == 1
    assert outcome.raw_output_bytes == len(artifact)
    assert len(outcome.raw_preview) == 1


@dataclass
class _Engine:
    payload: bytes
    requests: list[ValidatedCommandRequest] = field(default_factory=list)

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        self.requests.append(request)
        arguments = tuple(request.arguments)
        output_directory = Path(arguments[arguments.index("--output-directory") + 1])
        (output_directory / OUTPUT_ARTIFACT_FILENAME).write_bytes(self.payload)
        return CommandResult(
            specification=ExecutionSpecification.from_request(request),
            return_code=0,
            stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
        )


@dataclass
class _EngineFactory:
    engine: _Engine
    calls: int = 0

    def create(self) -> _Engine:
        self.calls += 1
        return self.engine


@dataclass
class _NoCredentialLeaseFactory:
    calls: int = 0

    def create(self, secret: Any, *, suffix: str) -> Any:
        del secret, suffix
        self.calls += 1
        raise AssertionError("AWS must not create a temporary credential file")


def test_fake_engine_proves_exact_aws_subprocess_arguments(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """The real client composition emits exact non-shell full-scope argv."""
    engine = _Engine(json.dumps([ocsf_record_factory("argv")]).encode())
    engine_factory = _EngineFactory(engine)
    leases = _NoCredentialLeaseFactory()
    contract = _contract()
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)

    contract.execute(
        ProwlerConfig(executable_path="/fake/prowler"), contract.parse_input(aws_form)
    )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    request = engine.requests[0]
    assert tuple(request.arguments) == (
        "aws",
        "--region",
        "eu-west-1",
        "--severity",
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "--output-directory",
        request.arguments[request.arguments.index("--output-directory") + 1],
        "--output-filename",
        "findings",
        "-z",
        "--only-logs",
        "--no-color",
        "-M",
        "json-ocsf",
    )
    assert tuple(request.environment) == (
        ("AWS_ACCESS_KEY_ID", SecretStr("CANARY-ACCESS-KEY")),
        ("AWS_SECRET_ACCESS_KEY", SecretStr("CANARY-SECRET-KEY")),
        ("AWS_SESSION_TOKEN", SecretStr("CANARY-SESSION-TOKEN")),
        ("AWS_ENDPOINT_URL", "https://aws.internal.example:8443"),
    )
    assert "-c" not in request.arguments
    assert leases.calls == 0


def test_mapping_filters_normalizes_and_preserves_all_fields_in_order(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """CHK.005 mapping is retained while non-AWS findings are excluded."""
    records = [
        ocsf_record_factory("first", provider="AWS", status="PASS"),
        ocsf_record_factory("excluded", provider="Azure", status="FAIL"),
        ocsf_record_factory("second", provider="aws", status="MUTED"),
    ]
    artifact = json.dumps(records).encode()
    factory = _ClientFactory(
        CommandResult(
            specification=_specification(),
            return_code=0,
            stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
            parsed=artifact,
        )
    )
    contract = _contract()
    contract._client_factory = factory

    first = contract.execute(ProwlerConfig(), contract.parse_input(aws_form)).findings
    second = contract.execute(ProwlerConfig(), contract.parse_input(aws_form)).findings

    assert tuple(item.value for item in first) == ("first", "second")
    assert tuple(item.cloud_provider for item in first) == ("aws", "aws")
    assert tuple(item.expectation_result for item in first) == ("SUCCESS", "IGNORED")
    assert first == second
    assert all(
        tuple(item.model_dump()) == tuple(OpenAevFinding.model_fields) for item in first
    )


class _InjectApi:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def execution_reception(self, *, inject_id: str, data: dict[str, Any]) -> None:
        self.events.append(("reception", inject_id, data))

    def execution_callback(self, *, inject_id: str, data: dict[str, Any]) -> None:
        self.events.append(("callback", inject_id, data))


class _Helper:
    def __init__(self) -> None:
        self.api = type("Api", (), {})()
        self.api.inject = _InjectApi()
        self.injector_logger = RecordingLogger()


def _message(identifier: str, content: dict[str, object]) -> dict[str, object]:
    return {
        "injection": {
            "inject_id": "inject-chk007",
            "injector_contract_id": identifier,
            "inject_content": content,
        }
    }


def test_runtime_success_and_safe_error_are_end_to_end(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """Real extraction, mapping, Rich output, and terminal callbacks are exercised."""
    from prowler.injector import ProwlerInjector

    canaries = (
        "CANARY-ACCESS-KEY",
        "CANARY-SECRET-KEY",
        "CANARY-SESSION-TOKEN",
        "/tmp/credential-canary",  # noqa: S108 - deliberate leak canary
        "STDERR-CANARY",
        "CONSOLE-NON-JSON-CANARY",
    )
    artifact = json.dumps([ocsf_record_factory("runtime")]).encode()
    result = CommandResult(
        specification=_specification(
            ("/tmp/credential-canary",)  # noqa: S108 - deliberate leak canary
        ),
        return_code=0,
        stdout=b"\x1b[31mCONSOLE-NON-JSON-CANARY\x1b[0m",
        stderr=b"STDERR-CANARY",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    helper = _Helper()
    injector = ProwlerInjector(_config(), helper, registry=DEFAULT_PROWLER_CONTRACTS)
    identifier = str(stable_contract_id("aws"))

    injector.process_message(_message(identifier, aws_form))

    events = helper.api.inject.events
    assert tuple(event[0] for event in events) == ("reception", "callback")
    callback = events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    structured = json.loads(callback["execution_output_structured"])
    assert len(structured["findings"]) == 1
    mapped = json.loads(structured["findings"][0])
    assert mapped["value"] == "runtime"
    assert "runtime" in callback["execution_message"]
    assert callback["execution_message"].index("Prowler Findings") < callback[
        "execution_message"
    ].index("[PROWLER] Raw OCSF evidence (bounded preview)")
    assert "Total raw records: 1" in callback["execution_message"]
    assert f"Artifact bytes: {len(artifact)}" in callback["execution_message"]
    assert all(marker not in json.dumps(callback) for marker in canaries)
    assert len(factory.calls) == 1
    logs = helper.injector_logger.events
    assert tuple((event.level, event.message) for event in logs) == (
        ("info", _ASSESSMENT_RECEIVED),
        ("debug", _RECEPTION_ACKNOWLEDGED),
        ("debug", _CONTRACT_RESOLVED),
        ("debug", _ASSESSMENT_VALIDATED),
        ("info", _EXECUTION_STARTED),
        ("info", _ASSESSMENT_SUCCEEDED),
        ("debug", _CALLBACK_COMPLETED),
    )
    assert [event.metadata["stage"] for event in logs if event.metadata] == [
        "message_reception",
        "reception_acknowledged",
        "contract_resolution",
        "input_validation",
        "assessment_execution",
        "assessment_completion",
        "callback",
    ]
    assert all(event.metadata is not None for event in logs)
    assert all(
        event.metadata["inject_id"] == "inject-chk007"
        for event in logs
        if event.metadata
    )
    assert all(
        0 <= event.metadata["elapsed_ms"] <= 86_400_000
        for event in logs
        if event.metadata
    )
    for event in logs[2:]:
        assert event.metadata is not None
        assert event.metadata["contract_id"] == identifier
        assert event.metadata["route"] == "aws"
        assert event.metadata["provider"] == "aws"
    for event in logs[3:]:
        assert event.metadata is not None
        assert event.metadata["aws_account_id"] == "123456789012"
        assert event.metadata["aws_region"] == "eu-west-1"
        assert event.metadata["aws_session_token_present"] is True
        assert event.metadata["aws_endpoint_override_present"] is True
        assert event.metadata["aws_endpoint_origin"] == (
            "https://aws.internal.example:8443"
        )
    success_metadata = logs[5].metadata
    assert success_metadata is not None
    assert success_metadata["status"] == "SUCCESS"
    assert success_metadata["finding_count"] == 1
    assert success_metadata["vulnerability_count"] == 1
    assert success_metadata["raw_record_count"] == 1
    assert success_metadata["raw_output_bytes"] == len(artifact)
    callback_metadata = logs[6].metadata
    assert callback_metadata is not None
    assert callback_metadata["assessment_status"] == "SUCCESS"
    assert callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in callback_metadata
    assert "attempted_status" not in callback_metadata
    serialized_logs = repr(logs)
    assert all(marker not in serialized_logs for marker in canaries)

    invalid_helper = _Helper()
    invalid_injector = ProwlerInjector(
        _config(), invalid_helper, registry=DEFAULT_PROWLER_CONTRACTS
    )
    invalid_injector.process_message(
        _message(identifier, {**aws_form, "aws_account_id": "not-an-account"})
    )
    invalid_callback = invalid_helper.api.inject.events[1][2]
    assert invalid_callback["execution_status"] == "ERROR"
    assert all(marker not in json.dumps(invalid_callback) for marker in canaries)
    assert len(factory.calls) == 1
    invalid_logs = invalid_helper.injector_logger.events
    assert tuple((event.level, event.message) for event in invalid_logs) == (
        ("info", _ASSESSMENT_RECEIVED),
        ("debug", _RECEPTION_ACKNOWLEDGED),
        ("debug", _CONTRACT_RESOLVED),
        ("error", _ASSESSMENT_FAILED),
        ("debug", _CALLBACK_COMPLETED),
    )
    assert [event.metadata["stage"] for event in invalid_logs if event.metadata] == [
        "message_reception",
        "reception_acknowledged",
        "contract_resolution",
        "input_validation",
        "callback",
    ]
    assert all(event.metadata is not None for event in invalid_logs)
    assert all(
        event.metadata["inject_id"] == "inject-chk007"
        for event in invalid_logs
        if event.metadata
    )
    assert all(
        0 <= event.metadata["elapsed_ms"] <= 86_400_000
        for event in invalid_logs
        if event.metadata
    )
    for event in invalid_logs[2:]:
        assert event.metadata is not None
        assert event.metadata["contract_id"] == identifier
        assert event.metadata["route"] == "aws"
        assert event.metadata["provider"] == "aws"
    failure_metadata = invalid_logs[3].metadata
    assert failure_metadata is not None
    assert failure_metadata["status"] == "ERROR"
    assert failure_metadata["stage"] == "input_validation"
    assert failure_metadata["failure_kind"] == "invalid_input"
    assert failure_metadata["failure_summary"] == "The assessment input was invalid."
    assert failure_metadata["operator_guidance"] == (
        "AWS account ID must contain exactly 12 ASCII digits."
    )
    assert failure_metadata["issues"] == [
        {
            "location": ["aws", "aws_account_id"],
            "type": "string_pattern_mismatch",
        }
    ]
    assert invalid_logs[3].exc_info is False
    invalid_callback_metadata = invalid_logs[4].metadata
    assert invalid_callback_metadata is not None
    assert invalid_callback_metadata["assessment_status"] == "ERROR"
    assert invalid_callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in invalid_callback_metadata
    assert "attempted_status" not in invalid_callback_metadata
    serialized_invalid_logs = repr(invalid_logs)
    assert all(marker not in serialized_invalid_logs for marker in canaries)
