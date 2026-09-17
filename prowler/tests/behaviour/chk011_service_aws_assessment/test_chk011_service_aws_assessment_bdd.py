"""Raw pytest executable contract for CHK.011."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import SecretStr
from pyoaev.configuration import ConfigLoaderOAEV

from prowler._core.cli_engine import (CommandResult, ExecutionSpecification,
                                      OutputSpecification,
                                      ValidatedCommandRequest)
from prowler._core.prowler_client import (OUTPUT_ARTIFACT_FILENAME,
                                          ProwlerClientFactory)
from prowler.contracts import (CREDENTIAL_REFERENCE_KEY,
                               DEFAULT_PROWLER_CONTRACTS, AwsServiceContract,
                               stable_contract_id)
from prowler.models.configs.config_loader import (ConfigLoader, InjectorConfig,
                                                  ProwlerConfig)
from prowler.models.provider_inputs import AzureProviderInput

from .conftest import RecordingLogger

_ROUTES = (("aws/iam", "iam"), ("aws/s3", "s3"), ("aws/ec2", "ec2"))
_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"


def _specification() -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=(),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(parser="raw"),
        timeout_seconds=1.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _ClientFactory:
    result: CommandResult
    calls: list[tuple[Any, Any, tuple[str, ...], object]] = field(default_factory=list)

    def run(
        self,
        config: Any,
        provider: Any,
        *,
        check_filters: Any = (),
        service_selector: object = None,
    ) -> CommandResult:
        self.calls.append((config, provider, tuple(check_filters), service_selector))
        return self.result


def _contract(route: str) -> Any:
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


@pytest.mark.parametrize(("route", "service"), _ROUTES)
def test_route_selects_exact_service_once(
    route: str, service: str, aws_form: dict[str, object]
) -> None:
    """A route-owned selector crosses the client seam once without check filters."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory

    contract.execute(ProwlerConfig(), contract.parse_input(aws_form))

    assert len(factory.calls) == 1
    assert factory.calls[0][2:] == ((), service)


def test_registry_has_32_canonical_contracts_with_exact_provider_fields() -> None:
    """The public surface is ordered, stable, labelled, and exact on fields."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    routes = (
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        *(item[0] for item in _ROUTES),
        "azure/iam",
        "azure/storage",
        "gcp/iam",
        "gcp/compute",
        "cis/aws",
        "cis/azure",
        "cis/gcp",
        "cis/kubernetes",
        "nis2/aws",
        "nis2/azure",
        "nis2/gcp",
        "iso27001/aws",
        "iso27001/azure",
        "iso27001/gcp",
        "iso27001/kubernetes",
        "mitre/aws",
        "mitre/azure",
        "mitre/gcp",
        "aws/select-service",
        "aws/select-compliance",
        "azure/select-service",
        "azure/select-compliance",
        "gcp/select-service",
        "gcp/select-compliance",
        "universal",
    )

    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id(route)) for route in routes
    ]
    for item, (route, service) in zip(serialized[4:7], _ROUTES, strict=True):
        content = json.loads(item["contract_content"])
        assert service.upper() in content["label"]["en"]
        assert tuple(field["key"] for field in content["fields"]) == (
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_account_id",
            "aws_region",
            "aws_endpoint_url",
            "aws_session_token",
            CREDENTIAL_REFERENCE_KEY,
        )
        assert all(route in output["labels"] for output in content["outputs"])


def test_unsupported_contract_selector_is_rejected_pre_client(
    aws_form: dict[str, object],
) -> None:
    """Invalid route metadata cannot consume the CHK.004 seam."""

    class InvalidServiceContract(AwsServiceContract):
        contract_id = str(stable_contract_id("aws/iam"))
        external_id = "prowler:aws/iam"
        route_name = "aws/iam"
        label = "Invalid"
        service_selector = cast(Any, "lambda")

    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = InvalidServiceContract(factory)

    with pytest.raises(ValueError, match="unsupported AWS service selector"):
        contract.execute(ProwlerConfig(), contract.parse_input(aws_form))

    assert factory.calls == []


def test_mapping_order_shared_outputs_and_safe_trace(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """Keep ordered service-free output while identifying safe route context."""
    records = [
        ocsf_record_factory("first", provider="AWS"),
        ocsf_record_factory("excluded", provider="azure"),
        ocsf_record_factory("second", status="PASS"),
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
    contract = _contract("aws/iam")
    contract._client_factory = factory
    provider = contract.parse_input(aws_form)

    outcome = contract.execute(ProwlerConfig(), provider)
    payload = contract.output_payload(outcome.findings)
    trace = contract.render_trace(
        provider,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )

    assert tuple(item.value for item in outcome.findings) == ("first", "second")
    assert all("service" not in item.model_dump() for item in outcome.findings)
    assert tuple(json.loads(item)["value"] for item in payload["findings"]) == (
        "first",
        "second",
    )
    assert "aws/iam" in trace
    assert "service=iam" in trace
    assert outcome.raw_record_count == 3
    assert outcome.raw_output_bytes == len(artifact)
    assert trace.index("Prowler Findings") < trace.index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    credential_canaries = (
        aws_form["aws_access_key_id"],
        aws_form["aws_secret_access_key"],
        aws_form["aws_session_token"],
    )
    assert all(str(marker) not in trace for marker in credential_canaries)


@dataclass
class _Engine:
    payload: bytes
    requests: list[ValidatedCommandRequest] = field(default_factory=list)

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        self.requests.append(request)
        arguments = tuple(request.arguments)
        output_directory = Path(arguments[arguments.index("--output-directory") + 1])
        (output_directory / OUTPUT_ARTIFACT_FILENAME).write_bytes(self.payload)
        specification = ExecutionSpecification.from_request(request)
        return CommandResult(
            specification=ExecutionSpecification(
                executable=specification.executable,
                arguments=(*specification.arguments, "ARGV-CANARY"),
                environment=(
                    *specification.environment,
                    ("ENV-NAME-CANARY", "ENV-VALUE-CANARY"),
                ),
                working_directory="/tmp/TEMP-WORKDIR-CANARY",  # noqa: S108
                input_bytes=specification.input_bytes,
                output=specification.output,
                timeout_seconds=specification.timeout_seconds,
                maximum_accepted_output_bytes=(
                    specification.maximum_accepted_output_bytes
                ),
            ),
            return_code=0,
            stdout=b"\x1b[31mCONSOLE-NON-JSON-CANARY\x1b[0m",
            stderr=b"STDERR-CANARY",
        )


@dataclass
class _EngineFactory:
    engine: _Engine
    calls: int = 0

    def create(self) -> _Engine:
        self.calls += 1
        return self.engine


@dataclass
class _NoLeaseFactory:
    calls: int = 0

    def create(self, secret: Any, *, suffix: str) -> Any:
        del secret, suffix
        self.calls += 1
        raise AssertionError("AWS must not create credential files")


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


def _config() -> ConfigLoader:
    return ConfigLoader.model_construct(
        openaev=ConfigLoaderOAEV(
            url="http://127.0.0.1:8080", token="runtime-placeholder"
        ),
        injector=InjectorConfig(id="injector-test"),
        prowler=ProwlerConfig(executable_path="/fake/prowler"),
    )


def _message(route: str, service: str, content: dict[str, object]) -> dict[str, object]:
    return {
        "injection": {
            "inject_id": f"inject-{service}",
            "injector_contract_id": str(stable_contract_id(route)),
            "inject_content": content,
        }
    }


@pytest.mark.parametrize(("route", "service"), _ROUTES)
def test_runtime_one_call_exact_service_argv_and_canaries(
    route: str,
    service: str,
    aws_form: dict[str, object],
    ocsf_record_factory: Any,
) -> None:
    """The full runtime uses one fake execution and emits exact non-shell argv."""
    from prowler.injector import ProwlerInjector

    finding_name = f"CALLBACK-FINDING-CANARY-{service}"
    engine = _Engine(json.dumps([ocsf_record_factory(finding_name)]).encode())
    engine_factory = _EngineFactory(engine)
    leases = _NoLeaseFactory()
    contract = _contract(route)
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)
    helper = _Helper()
    ProwlerInjector(_config(), helper).process_message(
        _message(route, service, aws_form)
    )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    assert tuple(engine.requests[0].arguments) == (
        "aws",
        "--region",
        "eu-west-1",
        "--services",
        service,
        "--output-directory",
        engine.requests[0].arguments[
            engine.requests[0].arguments.index("--output-directory") + 1
        ],
        "--output-filename",
        "findings",
        "-z",
        "--only-logs",
        "--no-color",
        "-M",
        "json-ocsf",
    )
    assert tuple(engine.requests[0].environment) == (
        ("AWS_ACCESS_KEY_ID", SecretStr("CANARY-ACCESS-KEY")),
        ("AWS_SECRET_ACCESS_KEY", SecretStr("CANARY-SECRET-KEY")),
        ("AWS_SESSION_TOKEN", SecretStr("CANARY-SESSION-TOKEN")),
        ("AWS_ENDPOINT_URL", "https://aws.internal.example:8443"),
    )
    assert str(aws_form["aws_endpoint_url"]) not in engine.requests[0].arguments
    assert "AWS_ENDPOINT_URL" not in engine.requests[0].arguments
    assert "-c" not in engine.requests[0].arguments
    assert tuple(event[0] for event in helper.api.inject.events) == (
        "reception",
        "callback",
    )
    callback = helper.api.inject.events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    callback_sensitive_canaries = (
        aws_form["aws_access_key_id"],
        aws_form["aws_secret_access_key"],
        aws_form["aws_session_token"],
        aws_form["aws_endpoint_url"],
        "ARGV-CANARY",
        "ENV-NAME-CANARY",
        "ENV-VALUE-CANARY",
        "STDERR-CANARY",
        "CONSOLE-NON-JSON-CANARY",
        "/tmp/TEMP-WORKDIR-CANARY",  # noqa: S108 - deliberate leak canary
    )
    serialized_callback = json.dumps(callback)
    assert finding_name in serialized_callback
    assert all(
        str(marker) not in serialized_callback for marker in callback_sensitive_canaries
    )
    assert leases.calls == 0

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
        event.metadata["inject_id"] == f"inject-{service}"
        for event in logs
        if event.metadata
    )
    assert all(
        0 <= event.metadata["elapsed_ms"] <= 86_400_000
        for event in logs
        if event.metadata
    )
    identifier = str(stable_contract_id(route))
    for event in logs[2:]:
        assert event.metadata is not None
        assert event.metadata["contract_id"] == identifier
        assert event.metadata["route"] == route
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
    assert success_metadata["raw_output_bytes"] == len(engine.payload)
    callback_metadata = logs[6].metadata
    assert callback_metadata is not None
    assert callback_metadata["assessment_status"] == "SUCCESS"
    assert callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in callback_metadata
    assert "attempted_status" not in callback_metadata
    log_canaries = (
        aws_form["aws_access_key_id"],
        aws_form["aws_secret_access_key"],
        aws_form["aws_session_token"],
        "ARGV-CANARY",
        "ENV-NAME-CANARY",
        "ENV-VALUE-CANARY",
        "STDERR-CANARY",
        "/tmp/TEMP-WORKDIR-CANARY",  # noqa: S108 - deliberate leak canary
        finding_name,
        "EXCEPTION-FIELD-CANARY",
        "EXCEPTION-VALUE-CANARY",
    )
    assert all(str(marker) not in repr(logs) for marker in log_canaries)

    invalid_helper = _Helper()
    ProwlerInjector(_config(), invalid_helper).process_message(
        _message(
            route,
            service,
            {
                **aws_form,
                "aws_account_id": "INVALID-ACCOUNT-CANARY",
                "EXCEPTION-FIELD-CANARY": "EXCEPTION-VALUE-CANARY",
            },
        )
    )

    assert tuple(event[0] for event in invalid_helper.api.inject.events) == (
        "reception",
        "callback",
    )
    invalid_callback = invalid_helper.api.inject.events[1][2]
    assert invalid_callback["execution_status"] == "ERROR"
    invalid_callback_canaries = (
        *callback_sensitive_canaries,
        "INVALID-ACCOUNT-CANARY",
        "EXCEPTION-FIELD-CANARY",
        "EXCEPTION-VALUE-CANARY",
    )
    assert all(
        str(marker) not in json.dumps(invalid_callback)
        for marker in invalid_callback_canaries
    )
    assert engine_factory.calls == 1

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
        event.metadata["inject_id"] == f"inject-{service}"
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
        assert event.metadata["route"] == route
        assert event.metadata["provider"] == "aws"
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
            "location": ["aws", "aws_account_id"],
            "type": "string_pattern_mismatch",
        },
        {
            "location": ["aws", "unrecognized_field"],
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
    assert all(str(marker) not in repr(invalid_logs) for marker in log_canaries)
    assert "INVALID-ACCOUNT-CANARY" not in repr(invalid_logs)


def test_service_aws_endpoint_url_remains_optional(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """Omitting the optional endpoint leaves both environment and argv unchanged."""
    engine = _Engine(json.dumps([ocsf_record_factory("iam")]).encode())
    contract = _contract("aws/iam")
    contract._client_factory = ProwlerClientFactory(
        _EngineFactory(engine), _NoLeaseFactory()
    )
    form_without_endpoint = {
        key: value for key, value in aws_form.items() if key != "aws_endpoint_url"
    }

    contract.execute(ProwlerConfig(), contract.parse_input(form_without_endpoint))

    assert "AWS_ENDPOINT_URL" not in dict(engine.requests[0].environment)
    assert "AWS_ENDPOINT_URL" not in engine.requests[0].arguments
    service_index = engine.requests[0].arguments.index("--services")
    assert tuple(engine.requests[0].arguments[service_index : service_index + 2]) == (
        "--services",
        "iam",
    )


def test_existing_check_filter_argv_is_unchanged(
    aws_form: dict[str, object], ocsf_record_factory: Any
) -> None:
    """The selector seam does not repurpose or remove CHK.004 check filtering."""
    engine = _Engine(json.dumps([ocsf_record_factory("existing")]).encode())
    factory = ProwlerClientFactory(_EngineFactory(engine), _NoLeaseFactory())
    provider = _contract("aws").parse_input(aws_form)

    factory.run(
        ProwlerConfig(executable_path="/fake/prowler"),
        provider,
        check_filters=("check-one",),
    )

    check_index = engine.requests[0].arguments.index("-c")
    assert tuple(engine.requests[0].arguments[check_index : check_index + 2]) == (
        "-c",
        "check-one",
    )
    assert "--services" not in engine.requests[0].arguments


def test_aws_service_selector_rejects_azure_before_engine() -> None:
    """Provider/selector combinations are validated before any CLI call."""
    engine = _Engine(b"[]")
    factory = ProwlerClientFactory(_EngineFactory(engine), _NoLeaseFactory())
    provider = AzureProviderInput(
        provider="azure",
        azure_client_id="client",
        azure_client_secret="secret",
        azure_tenant_id="tenant",
        azure_subscription_id="subscription",
        azure_provider="azure",
    )

    with pytest.raises(ValueError, match="AWS service selector"):
        factory.run(ProwlerConfig(), provider, service_selector="s3")

    assert engine.requests == []
