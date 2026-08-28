"""Raw pytest executable contract for CHK.012."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from pyoaev.configuration import ConfigLoaderOAEV

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
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
from prowler.models.provider_inputs import AwsProviderInput

from .conftest import RecordingLogger

_ROUTES = (("azure/iam", "iam"), ("azure/storage", "storage"))
_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"


def _specification(arguments: tuple[str, ...] = ()) -> ExecutionSpecification:
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=arguments,
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
    route: str, service: str, azure_form: dict[str, object]
) -> None:
    """A route-owned selector crosses the client seam once without check filters."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory

    contract.execute(ProwlerConfig(), contract.parse_input(azure_form))

    assert len(factory.calls) == 1
    assert factory.calls[0][2:] == ((), service)


def test_registry_has_exact_eleven_canonical_contracts_without_selector_fields() -> (
    None
):
    """The public surface is ordered, stable, labelled, and not user-selectable."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    routes = (
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "aws/iam",
        "aws/s3",
        "aws/ec2",
        *(item[0] for item in _ROUTES),
        "gcp/iam",
        "gcp/compute",
    )

    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id(route)) for route in routes
    ]
    for item, (route, service) in zip(serialized[7:9], _ROUTES, strict=True):
        content = json.loads(item["contract_content"])
        assert service.casefold() in content["label"]["en"].casefold()
        assert tuple(field["key"] for field in content["fields"]) == (
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
            "azure_subscription_id",
            "azure_provider",
        )
        assert all(route in output["labels"] for output in content["outputs"])


def test_unsupported_contract_selector_is_rejected_pre_client(
    azure_form: dict[str, object],
) -> None:
    """Invalid route metadata cannot consume the CHK.004 seam."""
    import prowler.contracts as contract_api

    service_contract = cast(Any, contract_api.__dict__["AzureServiceContract"])

    class InvalidServiceContract(service_contract):
        contract_id = str(stable_contract_id("azure/iam"))
        external_id = "prowler:azure/iam"
        route_name = "azure/iam"
        label = "Invalid"
        service_selector = "keyvault"

    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = InvalidServiceContract(factory)

    with pytest.raises(ValueError, match="unsupported Azure service selector"):
        contract.execute(ProwlerConfig(), contract.parse_input(azure_form))

    assert factory.calls == []


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
def test_blank_provider_field_is_rejected_pre_client(
    azure_form: dict[str, object], field_name: str
) -> None:
    """Service routes inherit structural nonblank validation before execution."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract("azure/iam")
    contract._client_factory = factory

    with pytest.raises(ValueError):
        contract.parse_input({**azure_form, field_name: " \t"})

    assert factory.calls == []


def test_nonblank_provider_fields_receive_no_semantic_or_live_validation() -> None:
    """Opaque nonblank identifiers parse locally without cloud access."""
    contract = _contract("azure/storage")
    provider = contract.parse_input(
        {
            "azure_tenant_id": "!",
            "azure_client_id": "?",
            "azure_client_secret": "#",
            "azure_subscription_id": "$",
            "azure_provider": "%",
        }
    )

    assert provider.azure_tenant_id == "!"
    assert provider.azure_subscription_id == "$"


def test_mapping_order_shared_outputs_and_dynamic_trace(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """Keep ordered CHK.005 output while tracing the same dynamic findings."""
    records = [
        azure_ocsf_record_factory("first", provider="Azure", status="PASS"),
        azure_ocsf_record_factory("excluded", provider="aws", status="FAIL"),
        azure_ocsf_record_factory("second", status="FAIL"),
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
    contract = _contract("azure/storage")
    contract._client_factory = factory
    provider = contract.parse_input(azure_form)

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
    assert tuple(json.loads(item)["value"] for item in payload["findings"]) == (
        "first",
        "second",
    )
    assert tuple(item["name"] for item in payload["vulnerabilities"]) == ("second",)
    assert all(name in trace for name in ("first", "second"))
    raw_section_index = trace.index("[PROWLER] Raw OCSF evidence (bounded preview)")
    assert "excluded" not in trace[:raw_section_index]
    assert trace.index("Prowler Findings") < raw_section_index
    assert outcome.raw_record_count == 3
    assert outcome.raw_output_bytes == len(artifact)
    assert "azure/storage" in trace
    assert "service=storage" in trace
    canaries = (
        azure_form["azure_tenant_id"],
        azure_form["azure_client_id"],
        azure_form["azure_client_secret"],
    )
    assert all(str(marker) not in trace for marker in canaries)


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
                arguments=(*specification.arguments, "PROCESS-ARGV-CANARY"),
                environment=(
                    *specification.environment,
                    ("PROCESS-ENV-NAME-CANARY", "PROCESS-ENV-VALUE-CANARY"),
                ),
                working_directory="/tmp/PROCESS-WORKDIR-CANARY",  # noqa: S108
                input_bytes=specification.input_bytes,
                output=specification.output,
                timeout_seconds=specification.timeout_seconds,
                maximum_accepted_output_bytes=(
                    specification.maximum_accepted_output_bytes
                ),
            ),
            return_code=0,
            stdout=b"\x1b[31mPROCESS-STDOUT-CANARY\x1b[0m",
            stderr=b"PROCESS-STDERR-CANARY",
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
        raise AssertionError("Azure must not create credential files")


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
def test_runtime_one_call_exact_service_argv_outputs_and_canaries(
    route: str,
    service: str,
    azure_form: dict[str, object],
    azure_ocsf_record_factory: Any,
) -> None:
    """The full runtime uses one fake execution and preserves safe dynamic output."""
    from prowler.injector import ProwlerInjector

    callback_name = f"CALLBACK-CANARY-{service}"
    finding_name = f"FINDING-CANARY-{service}"
    records = [
        azure_ocsf_record_factory(callback_name, status="PASS"),
        azure_ocsf_record_factory(finding_name, status="FAIL"),
        azure_ocsf_record_factory("excluded", provider="aws", status="FAIL"),
    ]
    engine = _Engine(json.dumps(records).encode())
    engine_factory = _EngineFactory(engine)
    leases = _NoLeaseFactory()
    contract = _contract(route)
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)
    helper = _Helper()
    ProwlerInjector(_config(), helper).process_message(
        _message(route, service, azure_form)
    )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    assert tuple(engine.requests[0].arguments) == (
        "azure",
        "--sp-env-auth",
        "--subscription-id",
        "SUBSCRIPTION-CANARY",
        "--azure-region",
        "PROVIDER-CANARY",
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
    assert "-c" not in engine.requests[0].arguments
    assert tuple(event[0] for event in helper.api.inject.events) == (
        "reception",
        "callback",
    )
    callback = helper.api.inject.events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    mapped_names = (callback_name, finding_name)
    structured = json.loads(callback["execution_output_structured"])
    assert tuple(json.loads(item)["value"] for item in structured["findings"]) == (
        mapped_names
    )
    assert tuple(item["name"] for item in structured["vulnerabilities"]) == (
        finding_name,
    )
    assert all(name in callback["execution_message"] for name in mapped_names)
    raw_section_index = callback["execution_message"].index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    assert "excluded" not in callback["execution_message"][:raw_section_index]
    assert str(azure_form["azure_subscription_id"]) in callback["execution_message"]
    assert str(azure_form["azure_provider"]) in callback["execution_message"]
    callback_excluded_canaries = (
        azure_form["azure_tenant_id"],
        azure_form["azure_client_id"],
        azure_form["azure_client_secret"],
        "FORM-CANARY",
        "PROCESS-ARGV-CANARY",
        "PROCESS-ENV-NAME-CANARY",
        "PROCESS-ENV-VALUE-CANARY",
        "PROCESS-STDOUT-CANARY",
        "PROCESS-STDERR-CANARY",
        "/tmp/PROCESS-WORKDIR-CANARY",  # noqa: S108 - deliberate leak canary
        "EXCEPTION-FIELD-CANARY",
        "EXCEPTION-VALUE-CANARY",
    )
    assert all(
        str(marker) not in json.dumps(callback) for marker in callback_excluded_canaries
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
        assert event.metadata["provider"] == "azure"
    for event in logs[3:]:
        assert event.metadata is not None
        assert event.metadata["azure_tenant_id_present"] is True
        assert event.metadata["azure_client_id_present"] is True
        assert event.metadata["azure_client_secret_present"] is True
        assert event.metadata["azure_subscription_id"] == "SUBSCRIPTION-CANARY"
        assert event.metadata["azure_provider"] == "PROVIDER-CANARY"
    success_metadata = logs[5].metadata
    assert success_metadata is not None
    assert success_metadata["status"] == "SUCCESS"
    assert success_metadata["finding_count"] == 2
    assert success_metadata["vulnerability_count"] == 1
    assert success_metadata["raw_record_count"] == 3
    assert success_metadata["raw_output_bytes"] == len(engine.payload)
    callback_metadata = logs[6].metadata
    assert callback_metadata is not None
    assert callback_metadata["assessment_status"] == "SUCCESS"
    assert callback_metadata["delivery_status"] == "SUCCESS"
    assert "status" not in callback_metadata
    assert "attempted_status" not in callback_metadata
    log_excluded_canaries = (
        *callback_excluded_canaries,
        callback_name,
        finding_name,
    )
    assert all(str(marker) not in repr(logs) for marker in log_excluded_canaries)

    invalid_helper = _Helper()
    ProwlerInjector(_config(), invalid_helper).process_message(
        _message(
            route,
            service,
            {
                **azure_form,
                "azure_subscription_id": " ",
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
    assert all(
        str(marker) not in json.dumps(invalid_callback)
        for marker in log_excluded_canaries
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
        assert event.metadata["provider"] == "azure"
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
            "location": ["azure", "azure_subscription_id"],
            "type": "value_error",
        },
        {
            "location": ["azure", "unrecognized_field"],
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
    assert all(
        str(marker) not in repr(invalid_logs) for marker in log_excluded_canaries
    )


def test_existing_check_filter_argv_is_unchanged(
    azure_form: dict[str, object], azure_ocsf_record_factory: Any
) -> None:
    """The selector seam does not repurpose or remove CHK.004 check filtering."""
    engine = _Engine(json.dumps([azure_ocsf_record_factory("existing")]).encode())
    factory = ProwlerClientFactory(_EngineFactory(engine), _NoLeaseFactory())
    provider = _contract("azure").parse_input(azure_form)

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


def test_azure_service_selector_rejects_aws_before_engine() -> None:
    """Provider/selector combinations are validated before any CLI call."""
    engine = _Engine(b"[]")
    factory = ProwlerClientFactory(_EngineFactory(engine), _NoLeaseFactory())
    provider = AwsProviderInput(
        provider="aws",
        aws_access_key_id="access",
        aws_secret_access_key="secret",
        aws_account_id="123456789012",
        aws_region="eu-west-1",
    )

    with pytest.raises(ValueError, match="Azure service selector"):
        factory.run(ProwlerConfig(), provider, service_selector=cast(Any, "storage"))

    assert engine.requests == []
