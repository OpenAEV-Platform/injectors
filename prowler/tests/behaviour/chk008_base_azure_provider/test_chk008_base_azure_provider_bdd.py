"""Raw pytest executable contract for CHK.008."""

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
        return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("azure")))
    except LookupError:
        pytest.fail("CHK.008 Azure base contract is not registered")


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
    """Azure remains second as the canonical registry grows through CHK.014."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    expected_id = stable_contract_id("azure")

    assert len(serialized) == 22
    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id("aws")),
        str(expected_id),
        str(stable_contract_id("gcp")),
        str(stable_contract_id("kubernetes")),
        str(stable_contract_id("aws/iam")),
        str(stable_contract_id("aws/s3")),
        str(stable_contract_id("aws/ec2")),
        str(stable_contract_id("azure/iam")),
        str(stable_contract_id("azure/storage")),
        str(stable_contract_id("gcp/iam")),
        str(stable_contract_id("gcp/compute")),
        str(stable_contract_id("cis/aws")),
        str(stable_contract_id("cis/azure")),
        str(stable_contract_id("cis/gcp")),
        str(stable_contract_id("cis/kubernetes")),
        str(stable_contract_id("nis2/aws")),
        str(stable_contract_id("nis2/azure")),
        str(stable_contract_id("nis2/gcp")),
        str(stable_contract_id("iso27001/aws")),
        str(stable_contract_id("iso27001/azure")),
        str(stable_contract_id("iso27001/gcp")),
        str(stable_contract_id("iso27001/kubernetes")),
    ]
    assert UUID(serialized[1]["contract_id"]) == expected_id
    assert expected_id.version == 5
    content = json.loads(serialized[1]["contract_content"])
    assert content["external_id"] == "prowler:azure"
    assert tuple(field["key"] for field in content["fields"]) == (
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "azure_provider",
    )
    assert tuple(output["field"] for output in content["outputs"]) == (
        "findings",
        "vulnerabilities",
    )


@pytest.mark.parametrize(
    "field_name",
    (
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "azure_provider",
    ),
)
def test_structurally_blank_input_is_rejected_before_dispatch(
    azure_form: dict[str, object], field_name: str
) -> None:
    """Inherited Azure validation remains structural, local, and pre-dispatch."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract()
    contract._client_factory = factory

    with pytest.raises(ValueError):
        contract.parse_input({**azure_form, field_name: " \t"})

    assert factory.calls == []


def test_valid_request_invokes_client_once_without_narrowing(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """The concrete base route passes the complete Azure scope once."""
    artifact = json.dumps([azure_ocsf_record_factory("one")]).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[32mconsole output is not OCSF JSON\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory

    outcome = contract.execute(ProwlerConfig(), contract.parse_input(azure_form))

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
        raise AssertionError("Azure must not create a temporary credential file")


def test_fake_engine_proves_exact_azure_subprocess_arguments(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """The real client composition emits exact non-shell full-scope argv."""
    engine = _Engine(json.dumps([azure_ocsf_record_factory("argv")]).encode())
    engine_factory = _EngineFactory(engine)
    leases = _NoCredentialLeaseFactory()
    contract = _contract()
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)

    contract.execute(
        ProwlerConfig(executable_path="/fake/prowler"),
        contract.parse_input(azure_form),
    )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    request = engine.requests[0]
    assert tuple(request.arguments) == (
        "azure",
        "--sp-env-auth",
        "--subscription-id",
        "subscription-123",
        "--azure-region",
        "Microsoft.Compute",
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
    assert tuple(name for name, _ in request.environment) == (
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
    )
    assert not {"-c", "--service", "--services", "--compliance"}.intersection(
        request.arguments
    )
    assert leases.calls == 0


def test_mapping_filters_normalizes_preserves_order_and_projects_outputs(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """CHK.005 mappings feed ordered Azure, Text, and FAILED output projections."""
    records = [
        azure_ocsf_record_factory("first", provider="Azure", status="PASS"),
        azure_ocsf_record_factory("excluded", provider="AWS", status="FAIL"),
        azure_ocsf_record_factory("second", provider="azure", status="FAIL"),
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
        ProwlerConfig(), contract.parse_input(azure_form)
    ).findings
    payload = contract.output_payload(findings)

    assert tuple(item.value for item in findings) == ("first", "second")
    assert tuple(item.cloud_provider for item in findings) == ("azure", "azure")
    assert tuple(item.expectation_result for item in findings) == (
        "SUCCESS",
        "FAILED",
    )
    assert all(
        tuple(item.model_dump()) == tuple(OpenAevFinding.model_fields)
        for item in findings
    )
    assert tuple(json.loads(item)["value"] for item in payload["findings"]) == (
        "first",
        "second",
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
            "inject_id": "inject-chk008",
            "injector_contract_id": identifier,
            "inject_content": content,
        }
    }


def test_runtime_success_and_safe_error_are_end_to_end(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """Real extraction, mapping, Rich output, and terminal callbacks are exercised."""
    from prowler.injector import ProwlerInjector

    canaries = (
        "CANARY-TENANT",
        "CANARY-CLIENT",
        "CANARY-SECRET",
        "/tmp/credential-canary",  # noqa: S108 - deliberate leak canary
        "STDERR-CANARY",
        "CONSOLE-NON-JSON-CANARY",
    )
    records = [
        azure_ocsf_record_factory("runtime-pass", status="PASS"),
        azure_ocsf_record_factory("runtime-fail", status="FAIL"),
        azure_ocsf_record_factory("excluded", provider="aws", status="FAIL"),
    ]
    artifact = json.dumps(records).encode()
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
    identifier = str(stable_contract_id("azure"))

    injector.process_message(_message(identifier, azure_form))

    events = helper.api.inject.events
    assert tuple(event[0] for event in events) == ("reception", "callback")
    callback = events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    structured = json.loads(callback["execution_output_structured"])
    mapped_names = tuple(json.loads(item)["value"] for item in structured["findings"])
    assert mapped_names == ("runtime-pass", "runtime-fail")
    assert tuple(item["name"] for item in structured["vulnerabilities"]) == (
        "runtime-fail",
    )
    assert all(name in callback["execution_message"] for name in mapped_names)
    raw_section_index = callback["execution_message"].index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    assert "excluded" not in callback["execution_message"][:raw_section_index]
    assert callback["execution_message"].index("Prowler Findings") < raw_section_index
    assert "Total raw records: 3" in callback["execution_message"]
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
        event.metadata["inject_id"] == "inject-chk008"
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
        assert event.metadata["route"] == "azure"
        assert event.metadata["provider"] == "azure"
    for event in logs[3:]:
        assert event.metadata is not None
        assert event.metadata["azure_tenant_id_present"] is True
        assert event.metadata["azure_client_id_present"] is True
        assert event.metadata["azure_client_secret_present"] is True
        assert event.metadata["azure_subscription_id"] == "subscription-123"
        assert event.metadata["azure_provider"] == "Microsoft.Compute"
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
    serialized_logs = repr(logs)
    assert all(marker not in serialized_logs for marker in canaries)

    invalid_helper = _Helper()
    invalid_injector = ProwlerInjector(
        _config(), invalid_helper, registry=DEFAULT_PROWLER_CONTRACTS
    )
    invalid_injector.process_message(
        _message(identifier, {**azure_form, "azure_subscription_id": " "})
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
        event.metadata["inject_id"] == "inject-chk008"
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
        assert event.metadata["route"] == "azure"
        assert event.metadata["provider"] == "azure"
    failure_metadata = invalid_logs[3].metadata
    assert failure_metadata is not None
    assert failure_metadata["status"] == "ERROR"
    assert failure_metadata["stage"] == "input_validation"
    assert failure_metadata["failure_kind"] == "invalid_input"
    assert failure_metadata["failure_summary"] == "The assessment input was invalid."
    assert failure_metadata["operator_guidance"] == (
        "Azure subscription ID has an invalid value."
    )
    assert failure_metadata["issues"] == [
        {
            "location": ["azure", "azure_subscription_id"],
            "type": "value_error",
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
