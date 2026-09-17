"""Raw pytest executable contract for CHK.010."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
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
from prowler._core.prowler_client.credentials import TemporaryCredentialLeaseFactory
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
        return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("kubernetes")))
    except LookupError:
        pytest.fail("CHK.010 Kubernetes base contract is not registered")


def _config() -> ConfigLoader:
    return ConfigLoader.model_construct(
        openaev=ConfigLoaderOAEV(
            url="http://127.0.0.1:8080", token="runtime-placeholder"
        ),
        injector=InjectorConfig(id="injector-test"),
        prowler=ProwlerConfig(executable_path="/fake/prowler"),
    )


def _specification(
    arguments: tuple[str, ...] = (),
    environment: tuple[tuple[str, str], ...] = (),
) -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=arguments,
        environment=environment,
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
    """The four base routes remain first in the CHK.012 executable surface."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    expected_id = stable_contract_id("kubernetes")

    assert len(serialized) == 9
    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id("aws")),
        str(stable_contract_id("azure")),
        str(stable_contract_id("gcp")),
        str(expected_id),
        str(stable_contract_id("aws/iam")),
        str(stable_contract_id("aws/s3")),
        str(stable_contract_id("aws/ec2")),
        str(stable_contract_id("azure/iam")),
        str(stable_contract_id("azure/storage")),
    ]
    assert UUID(serialized[3]["contract_id"]) == expected_id
    assert expected_id.version == 5
    content = json.loads(serialized[3]["contract_content"])
    assert content["external_id"] == "prowler:kubernetes"
    assert tuple(field["key"] for field in content["fields"]) == (
        "kubernetes_kubeconfig",
        "kubernetes_context",
    )
    assert tuple(output["field"] for output in content["outputs"]) == (
        "findings",
        "vulnerabilities",
    )


@pytest.mark.parametrize(
    "field_name",
    (
        "kubernetes_kubeconfig",
        "kubernetes_context",
    ),
)
def test_structurally_blank_input_is_rejected_before_dispatch(
    kubernetes_form: dict[str, object], field_name: str
) -> None:
    """Inherited Kubernetes validation remains structural, local, and pre-dispatch."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract()
    contract._client_factory = factory

    with pytest.raises(ValueError):
        contract.parse_input({**kubernetes_form, field_name: " \t"})

    assert factory.calls == []


def test_valid_request_invokes_client_once_without_narrowing(
    kubernetes_form: dict[str, object], kubernetes_ocsf_record_factory: Any
) -> None:
    """The concrete base route passes the complete Kubernetes scope once."""
    artifact = json.dumps([kubernetes_ocsf_record_factory("one")]).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory

    outcome = contract.execute(ProwlerConfig(), contract.parse_input(kubernetes_form))

    assert len(factory.calls) == 1
    assert factory.calls[0][2] == ()
    assert len(outcome.findings) == 1
    assert outcome.raw_record_count == 1
    assert outcome.raw_output_bytes == len(artifact)
    assert len(outcome.raw_preview) == 1


@dataclass
class _Engine:
    payload: bytes
    outcome: str
    requests: list[ValidatedCommandRequest] = field(default_factory=list)
    credential_paths: list[Path] = field(default_factory=list)

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        self.requests.append(request)
        credential_path = Path(request.arguments[2])
        self.credential_paths.append(credential_path)
        assert (
            credential_path.read_text(encoding="utf-8")
            == "KUBECONFIG-CANARY\nFORM-CANARY"
        )
        if self.outcome == "raise":
            raise RuntimeError("fake engine failure")
        if self.outcome == "success":
            arguments = tuple(request.arguments)
            output_directory = Path(
                arguments[arguments.index("--output-directory") + 1]
            )
            (output_directory / OUTPUT_ARTIFACT_FILENAME).write_bytes(self.payload)
        return CommandResult(
            specification=ExecutionSpecification.from_request(request),
            return_code=0 if self.outcome == "success" else 2,
            stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
        )


@dataclass
class _EngineFactory:
    engine: _Engine
    calls: int = 0

    def create(self) -> _Engine:
        self.calls += 1
        return self.engine


@pytest.mark.parametrize("engine_outcome", ("success", "failure", "raise"))
def test_fake_engine_proves_exact_kubernetes_subprocess_arguments(
    kubernetes_form: dict[str, object],
    kubernetes_ocsf_record_factory: Any,
    tmp_path: Path,
    engine_outcome: str,
) -> None:
    """Exact full-scope argv uses and always removes one closed kubeconfig lease."""
    engine = _Engine(
        json.dumps([kubernetes_ocsf_record_factory("argv")]).encode(),
        engine_outcome,
    )
    engine_factory = _EngineFactory(engine)
    leases = TemporaryCredentialLeaseFactory(temporary_root=tmp_path)
    contract = _contract()
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)

    if engine_outcome == "raise":
        with pytest.raises(RuntimeError, match="fake engine failure"):
            contract.execute(
                ProwlerConfig(executable_path="/fake/prowler"),
                contract.parse_input(kubernetes_form),
            )
    else:
        contract.execute(
            ProwlerConfig(executable_path="/fake/prowler"),
            contract.parse_input(kubernetes_form),
        )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    request = engine.requests[0]
    assert tuple(request.arguments) == (
        "kubernetes",
        "--kubeconfig-file",
        str(engine.credential_paths[0]),
        "--context",
        "CONTEXT-CANARY",
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
    assert request.environment == ()
    assert not {"-c", "--service", "--services", "--compliance"}.intersection(
        request.arguments
    )
    assert len(engine.credential_paths) == 1
    assert engine.credential_paths[0].suffix == ".yaml"
    assert not engine.credential_paths[0].exists()
    assert not engine.credential_paths[0].parent.exists()
    assert list(tmp_path.iterdir()) == []


def test_mapping_filters_normalizes_preserves_order_and_projects_outputs(
    kubernetes_form: dict[str, object], kubernetes_ocsf_record_factory: Any
) -> None:
    """CHK.005 mappings feed ordered Kubernetes, Text, and FAILED output projections."""
    records = [
        kubernetes_ocsf_record_factory("first", provider="Kubernetes", status="PASS"),
        kubernetes_ocsf_record_factory("excluded", provider="AWS", status="FAIL"),
        kubernetes_ocsf_record_factory("second", provider="kubernetes", status="FAIL"),
        kubernetes_ocsf_record_factory("third", provider="KUBERNETES", status="ERROR"),
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

    findings = contract.execute(
        ProwlerConfig(), contract.parse_input(kubernetes_form)
    ).findings
    payload = contract.output_payload(findings)

    assert tuple(item.value for item in findings) == ("first", "second", "third")
    assert tuple(item.cloud_provider for item in findings) == (
        "kubernetes",
        "kubernetes",
        "kubernetes",
    )
    assert tuple(item.expectation_result for item in findings) == (
        "SUCCESS",
        "FAILED",
        "IGNORED",
    )
    assert all(
        tuple(item.model_dump()) == tuple(OpenAevFinding.model_fields)
        for item in findings
    )
    assert tuple(json.loads(item)["value"] for item in payload["findings"]) == (
        "first",
        "second",
        "third",
    )
    assert tuple(item["name"] for item in payload["vulnerabilities"]) == ("second",)


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
            "inject_id": "inject-chk010",
            "injector_contract_id": identifier,
            "inject_content": content,
        }
    }


def test_runtime_success_and_safe_error_are_end_to_end(
    kubernetes_form: dict[str, object], kubernetes_ocsf_record_factory: Any
) -> None:
    """Real extraction, mapping, Rich output, and terminal callbacks are exercised."""
    from prowler.injector import ProwlerInjector

    callback_sensitive_canaries = (
        "KUBECONFIG-CANARY\nFORM-CANARY",
        "KUBECONFIG-CANARY",
        "FORM-CANARY",
        "ARGV-CANARY",
        "ENV-NAME-CANARY",
        "ENV-VALUE-CANARY",
        "STDOUT-CANARY",
        "STDERR-CANARY",
        "/tmp/TEMP-CREDENTIAL-PATH-CANARY",  # noqa: S108 - leak canary
        "EXCEPTION-FIELD-CANARY",
        "EXCEPTION-VALUE-CANARY",
    )
    log_canaries = (
        *callback_sensitive_canaries,
        "CALLBACK-CANARY",
        "FINDING-CANARY",
    )
    records = [
        kubernetes_ocsf_record_factory("CALLBACK-CANARY", status="PASS"),
        kubernetes_ocsf_record_factory("FINDING-CANARY", status="FAIL"),
        kubernetes_ocsf_record_factory("excluded", provider="aws", status="FAIL"),
    ]
    artifact = json.dumps(records).encode()
    result = CommandResult(
        specification=_specification(
            (
                "ARGV-CANARY",
                "/tmp/TEMP-CREDENTIAL-PATH-CANARY",  # noqa: S108 - leak canary
            ),
            (("ENV-NAME-CANARY", "ENV-VALUE-CANARY"),),
        ),
        return_code=0,
        stdout=b"\x1b[31mSTDOUT-CANARY\x1b[0m",
        stderr=b"STDERR-CANARY",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    helper = _Helper()
    injector = ProwlerInjector(_config(), helper, registry=DEFAULT_PROWLER_CONTRACTS)
    identifier = str(stable_contract_id("kubernetes"))

    injector.process_message(_message(identifier, kubernetes_form))

    events = helper.api.inject.events
    assert tuple(event[0] for event in events) == ("reception", "callback")
    callback = events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    structured = json.loads(callback["execution_output_structured"])
    mapped_names = tuple(json.loads(item)["value"] for item in structured["findings"])
    assert mapped_names == ("CALLBACK-CANARY", "FINDING-CANARY")
    assert tuple(item["name"] for item in structured["vulnerabilities"]) == (
        "FINDING-CANARY",
    )
    assert all(name in callback["execution_message"] for name in mapped_names)
    raw_section_index = callback["execution_message"].index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    assert "excluded" not in callback["execution_message"][:raw_section_index]
    assert callback["execution_message"].index("Prowler Findings") < raw_section_index
    assert "Total raw records: 3" in callback["execution_message"]
    assert f"Artifact bytes: {len(artifact)}" in callback["execution_message"]
    serialized_callback = json.dumps(callback)
    assert (
        tuple(
            marker
            for marker in callback_sensitive_canaries
            if marker in serialized_callback
        )
        == ()
    )
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
        event.metadata["inject_id"] == "inject-chk010"
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
        assert event.metadata["route"] == "kubernetes"
        assert event.metadata["provider"] == "kubernetes"
    for event in logs[3:]:
        assert event.metadata is not None
        assert event.metadata["kubernetes_context"] == "CONTEXT-CANARY"
        assert event.metadata["kubernetes_credentials_present"] is True
    success_metadata = logs[5].metadata
    assert success_metadata is not None
    assert success_metadata["status"] == "SUCCESS"
    assert success_metadata["finding_count"] == 2
    assert success_metadata["vulnerability_count"] == 1
    assert success_metadata["raw_record_count"] == 3
    assert success_metadata["raw_output_bytes"] == len(artifact)
    callback_metadata = logs[6].metadata
    assert callback_metadata is not None
    assert callback_metadata["assessment_status"] == "SUCCESS"
    assert callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in callback_metadata
    assert "attempted_status" not in callback_metadata
    assert all(marker not in repr(logs) for marker in log_canaries)

    invalid_helper = _Helper()
    invalid_injector = ProwlerInjector(
        _config(), invalid_helper, registry=DEFAULT_PROWLER_CONTRACTS
    )
    invalid_injector.process_message(
        _message(
            identifier,
            {
                **kubernetes_form,
                "kubernetes_context": " ",
                "EXCEPTION-FIELD-CANARY": "EXCEPTION-VALUE-CANARY",
            },
        )
    )
    invalid_callback = invalid_helper.api.inject.events[1][2]
    assert invalid_callback["execution_status"] == "ERROR"
    serialized_invalid_callback = json.dumps(invalid_callback)
    assert (
        tuple(
            marker for marker in log_canaries if marker in serialized_invalid_callback
        )
        == ()
    )
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
        event.metadata["inject_id"] == "inject-chk010"
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
        assert event.metadata["route"] == "kubernetes"
        assert event.metadata["provider"] == "kubernetes"
    failure_metadata = invalid_logs[3].metadata
    assert failure_metadata is not None
    assert failure_metadata["status"] == "ERROR"
    assert failure_metadata["stage"] == "input_validation"
    assert failure_metadata["failure_kind"] == "invalid_input"
    assert failure_metadata["failure_summary"] == "The assessment input was invalid."
    assert failure_metadata["operator_guidance"] == (
        "Correct the listed assessment fields and retry."
    )
    assert failure_metadata["issues"] == [
        {
            "location": ["kubernetes", "kubernetes_context"],
            "type": "value_error",
        },
        {
            "location": ["kubernetes", "unrecognized_field"],
            "type": "extra_forbidden",
        },
    ]
    assert failure_metadata["issues_truncated"] is True
    assert invalid_logs[3].exc_info is False
    invalid_callback_metadata = invalid_logs[4].metadata
    assert invalid_callback_metadata is not None
    assert invalid_callback_metadata["assessment_status"] == "ERROR"
    assert invalid_callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in invalid_callback_metadata
    assert "attempted_status" not in invalid_callback_metadata
    assert all(marker not in repr(invalid_logs) for marker in log_canaries)
