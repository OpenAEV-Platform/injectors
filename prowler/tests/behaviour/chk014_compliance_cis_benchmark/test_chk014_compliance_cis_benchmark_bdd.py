"""Raw pytest executable contract for CHK.014."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast, get_args

import pytest
from pydantic import SecretStr
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

_ROUTES = (
    ("cis/aws", "aws", "cis_3.0_aws"),
    ("cis/azure", "azure", "cis_3.0_azure"),
    ("cis/gcp", "gcp", "cis_3.0_gcp"),
    ("cis/kubernetes", "kubernetes", "cis_1.12_kubernetes"),
)
_TEMP_PATHS = {
    "gcp": Path("/tmp/CANARY-GCP-CREDENTIAL.json"),  # noqa: S108
    "kubernetes": Path("/tmp/CANARY-KUBE-CREDENTIAL.yaml"),  # noqa: S108
}
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
    calls: list[tuple[Any, Any, tuple[str, ...], object, object]] = field(
        default_factory=list
    )

    def run(
        self,
        config: Any,
        provider: Any,
        *,
        check_filters: Any = (),
        service_selector: object = None,
        compliance_selector: object = None,
    ) -> CommandResult:
        self.calls.append(
            (
                config,
                provider,
                tuple(check_filters),
                service_selector,
                compliance_selector,
            )
        )
        return self.result


def _contract(route: str) -> Any:
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


@pytest.mark.parametrize(("route", "provider_name", "compliance"), _ROUTES)
def test_route_selects_exact_typed_compliance_once(
    route: str,
    provider_name: str,
    compliance: str,
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """A route-owned selector crosses the client seam once without other selectors."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory

    contract.execute(
        ProwlerConfig(), contract.parse_input(provider_forms[provider_name])
    )

    assert len(factory.calls) == 1
    assert factory.calls[0][2:] == ((), None, compliance)


def test_compliance_selector_type_contains_only_supported_cis_values() -> None:
    """The internal typed seam admits only the four evidenced Prowler values."""
    import prowler._core.prowler_client as client_api

    selector_type = client_api.__dict__.get("ComplianceSelector")

    assert selector_type is not None
    assert get_args(selector_type) == tuple(item[2] for item in _ROUTES)


def test_registry_has_exact_fifteen_canonical_contracts_without_selector_fields() -> (
    None
):
    """The executable public surface is stable, ordered, and not user-selectable."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    routes = (
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "aws/iam",
        "aws/s3",
        "aws/ec2",
        "azure/iam",
        "azure/storage",
        "gcp/iam",
        "gcp/compute",
        *(item[0] for item in _ROUTES),
    )

    assert [item["contract_id"] for item in serialized] == [
        str(stable_contract_id(route)) for route in routes
    ]
    for item, (route, provider_name, _) in zip(serialized[11:], _ROUTES, strict=True):
        content = json.loads(item["contract_content"])
        assert "cis" in content["label"]["en"].casefold()
        keys = tuple(field["key"] for field in content["fields"])
        assert keys
        assert all("compliance" not in key and "framework" not in key for key in keys)
        assert all(route in output["labels"] for output in content["outputs"])
        assert keys == tuple(
            field.key for field in _contract(provider_name).build_provider_fields()
        )


def test_unsupported_contract_selector_is_rejected_pre_client(
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """Invalid internal route metadata cannot consume the CHK.004 seam."""
    import prowler.contracts as contract_api

    cis_contract = contract_api.__dict__.get("CisComplianceContract")
    assert cis_contract is not None

    class InvalidCisContract(cis_contract):
        contract_id = str(stable_contract_id("cis/aws"))
        external_id = "prowler:cis/aws"
        route_name = "cis/aws"
        provider = "aws"
        label = "Invalid"
        compliance_selector = "cis_3.0_azure"

    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = InvalidCisContract(factory)

    with pytest.raises(ValueError, match="unsupported CIS compliance selection"):
        contract.execute(ProwlerConfig(), contract.parse_input(provider_forms["aws"]))

    assert factory.calls == []


def test_mapping_preserves_model_duplicates_compliance_outputs_and_trace(
    provider_forms: dict[str, dict[str, object]], cis_ocsf_record_factory: Any
) -> None:
    """Keep CHK.005 findings unchanged across all existing presentation channels."""
    duplicate = cis_ocsf_record_factory(
        "duplicate", compliance={"CIS-3.0": ["1.1", "1.1", "2.2"]}
    )
    records = [
        cis_ocsf_record_factory("first", status="PASS", compliance=["a", "b"]),
        duplicate,
        duplicate.copy(),
        cis_ocsf_record_factory("excluded", provider="azure"),
        cis_ocsf_record_factory("last", status="PASS", compliance=["z"]),
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
    contract = _contract("cis/aws")
    contract._client_factory = factory
    provider = contract.parse_input(provider_forms["aws"])

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

    expected = ("first", "duplicate", "duplicate", "last")
    assert tuple(item.value for item in outcome.findings) == expected
    assert tuple(item.compliance_tags for item in outcome.findings) == (
        ("a", "b"),
        ("CIS-3.0:1.1", "CIS-3.0:1.1", "CIS-3.0:2.2"),
        ("CIS-3.0:1.1", "CIS-3.0:1.1", "CIS-3.0:2.2"),
        ("z",),
    )
    assert tuple(json.loads(item)["value"] for item in payload["findings"]) == expected
    assert tuple(item["name"] for item in payload["vulnerabilities"]) == (
        "duplicate",
        "duplicate",
    )
    raw_section_index = trace.index("[PROWLER] Raw OCSF evidence (bounded preview)")
    rendered_rows = tuple(
        line
        for line in trace[:raw_section_index].splitlines()
        if any(name in line for name in ("first", "duplicate", "last"))
    )
    assert (
        tuple(next(name for name in expected if name in line) for line in rendered_rows)
        == expected
    )
    assert "excluded" not in trace[:raw_section_index]
    assert trace.index("Prowler Findings") < raw_section_index
    assert outcome.raw_record_count == 5
    assert outcome.raw_output_bytes == len(artifact)
    assert "cis/aws" in trace
    assert "compliance=cis_3.0_aws" in trace


@dataclass
class _Engine:
    payload: bytes
    lifecycle: list[str]
    requests: list[ValidatedCommandRequest] = field(default_factory=list)

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        self.lifecycle.append("engine")
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
class _CredentialLease:
    lifecycle: list[str]
    path: Path

    def cleanup(self) -> None:
        self.lifecycle.append("cleanup")


@dataclass
class _CredentialLeaseFactory:
    lifecycle: list[str]
    calls: list[tuple[SecretStr, str]] = field(default_factory=list)

    def create(self, secret: SecretStr, *, suffix: str) -> _CredentialLease:
        self.calls.append((secret, suffix))
        self.lifecycle.append(f"create:{suffix}")
        provider_name = "gcp" if suffix == ".json" else "kubernetes"
        return _CredentialLease(self.lifecycle, _TEMP_PATHS[provider_name])


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


def _message(
    route: str, provider_name: str, content: dict[str, object]
) -> dict[str, object]:
    return {
        "injection": {
            "inject_id": f"INJECT-ID-CANARY-{provider_name}",
            "injector_contract_id": str(stable_contract_id(route)),
            "inject_content": content,
        }
    }


@pytest.mark.parametrize(("route", "provider_name", "compliance"), _ROUTES)
def test_runtime_one_call_exact_compliance_argv_lifecycle_and_canaries(
    route: str,
    provider_name: str,
    compliance: str,
    provider_forms: dict[str, dict[str, object]],
    cis_ocsf_record_factory: Any,
) -> None:
    """Runtime uses one fake request and preserves provider resource handling."""
    from prowler.injector import ProwlerInjector

    callback_name = f"CALLBACK-CANARY-{provider_name}"
    finding_name = f"FINDING-CANARY-{provider_name}"
    records = [
        cis_ocsf_record_factory(callback_name, provider=provider_name, status="PASS"),
        cis_ocsf_record_factory(finding_name, provider=provider_name),
        cis_ocsf_record_factory("excluded", provider="unsupported"),
    ]
    lifecycle: list[str] = []
    engine = _Engine(json.dumps(records).encode(), lifecycle)
    engine_factory = _EngineFactory(engine)
    leases = _CredentialLeaseFactory(lifecycle)
    contract = _contract(route)
    contract._client_factory = ProwlerClientFactory(engine_factory, leases)
    helper = _Helper()

    ProwlerInjector(_config(), helper).process_message(
        _message(route, provider_name, provider_forms[provider_name])
    )

    assert engine_factory.calls == 1
    assert len(engine.requests) == 1
    arguments = tuple(engine.requests[0].arguments)
    compliance_index = arguments.index("--compliance")
    assert arguments[compliance_index : compliance_index + 2] == (
        "--compliance",
        compliance,
    )
    assert "-c" not in arguments
    assert "--services" not in arguments
    if provider_name in _TEMP_PATHS:
        suffix = ".json" if provider_name == "gcp" else ".yaml"
        assert lifecycle == [f"create:{suffix}", "engine", "cleanup"]
        assert len(leases.calls) == 1
    else:
        assert lifecycle == ["engine"]
        assert leases.calls == []
    assert tuple(event[0] for event in helper.api.inject.events) == (
        "reception",
        "callback",
    )
    callback = helper.api.inject.events[1][2]
    assert callback["execution_status"] == "SUCCESS"
    structured = json.loads(callback["execution_output_structured"])
    assert tuple(json.loads(item)["value"] for item in structured["findings"]) == (
        callback_name,
        finding_name,
    )
    assert tuple(item["name"] for item in structured["vulnerabilities"]) == (
        finding_name,
    )
    assert callback_name in callback["execution_message"]
    assert finding_name in callback["execution_message"]
    raw_section_index = callback["execution_message"].index(
        "[PROWLER] Raw OCSF evidence (bounded preview)"
    )
    assert "excluded" not in callback["execution_message"][:raw_section_index]
    trace_identifiers = {
        "aws": ("123456789012", "eu-west-1"),
        "azure": ("subscription-123", "Microsoft.Compute"),
        "gcp": ("acme-prod",),
        "kubernetes": ("acme-prod-cluster",),
    }
    assert all(
        marker in callback["execution_message"]
        for marker in trace_identifiers[provider_name]
    )
    assert route in callback["execution_message"]
    assert f"compliance={compliance}" in callback["execution_message"]
    credential_fields = {
        "aws": (
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
        ),
        "azure": (
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
        ),
        "gcp": ("gcp_service_account_json",),
        "kubernetes": ("kubernetes_kubeconfig",),
    }
    callback_excluded_canaries = tuple(
        str(provider_forms[provider_name][field_name])
        for field_name in credential_fields[provider_name]
    ) + (
        "PROCESS-ARGV-CANARY",
        "PROCESS-ENV-NAME-CANARY",
        "PROCESS-ENV-VALUE-CANARY",
        "PROCESS-STDOUT-CANARY",
        "PROCESS-STDERR-CANARY",
        "/tmp/PROCESS-WORKDIR-CANARY",  # noqa: S108 - deliberate leak canary
        *(str(path) for path in _TEMP_PATHS.values()),
        "EXCEPTION-FIELD-CANARY",
        "EXCEPTION-VALUE-CANARY",
    )
    assert all(
        marker not in json.dumps(callback) for marker in callback_excluded_canaries
    )

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
    inject_id = f"INJECT-ID-CANARY-{provider_name}"
    assert all(
        event.metadata["inject_id"] == inject_id for event in logs if event.metadata
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
        assert event.metadata["provider"] == provider_name
    safe_context = {
        "aws": {
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
            "aws_session_token_present": True,
            "aws_endpoint_override_present": False,
        },
        "azure": {
            "azure_tenant_id_present": True,
            "azure_client_id_present": True,
            "azure_client_secret_present": True,
            "azure_subscription_id": "subscription-123",
            "azure_provider": "Microsoft.Compute",
        },
        "gcp": {
            "gcp_project_id": "acme-prod",
            "gcp_credentials_present": True,
        },
        "kubernetes": {
            "kubernetes_context": "acme-prod-cluster",
            "kubernetes_credentials_present": True,
        },
    }
    for event in logs[3:]:
        assert event.metadata is not None
        assert all(
            event.metadata[key] == value
            for key, value in safe_context[provider_name].items()
        )
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
    assert all(marker not in repr(logs) for marker in log_excluded_canaries)

    invalid_fields = {
        "aws": "aws_account_id",
        "azure": "azure_subscription_id",
        "gcp": "gcp_project_id",
        "kubernetes": "kubernetes_context",
    }
    invalid_field = invalid_fields[provider_name]
    invalid_helper = _Helper()
    ProwlerInjector(_config(), invalid_helper).process_message(
        _message(
            route,
            provider_name,
            {
                **provider_forms[provider_name],
                invalid_field: " ",
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
        marker not in json.dumps(invalid_callback) for marker in log_excluded_canaries
    )
    assert engine_factory.calls == 1
    expected_lifecycle = (
        ["engine"]
        if provider_name not in _TEMP_PATHS
        else [
            "create:.json" if provider_name == "gcp" else "create:.yaml",
            "engine",
            "cleanup",
        ]
    )
    assert lifecycle == expected_lifecycle

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
        event.metadata["inject_id"] == inject_id
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
        assert event.metadata["provider"] == provider_name
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
        {"location": [provider_name, invalid_field], "type": "value_error"},
        {
            "location": [provider_name, "unrecognized_field"],
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
    assert all(marker not in repr(invalid_logs) for marker in log_excluded_canaries)


def test_existing_check_and_service_argv_are_unchanged(
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """Compliance selection does not repurpose either existing selector channel."""
    lifecycle: list[str] = []
    engine = _Engine(b"[]", lifecycle)
    factory = ProwlerClientFactory(
        _EngineFactory(engine), _CredentialLeaseFactory(lifecycle)
    )
    provider = _contract("aws").parse_input(provider_forms["aws"])

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
    assert "--compliance" not in engine.requests[0].arguments

    second_engine = _Engine(b"[]", [])
    second_factory = ProwlerClientFactory(
        _EngineFactory(second_engine), _CredentialLeaseFactory([])
    )
    second_provider = _contract("aws").parse_input(provider_forms["aws"])
    second_factory.run(
        ProwlerConfig(executable_path="/fake/prowler"),
        second_provider,
        service_selector="iam",
    )
    service_index = second_engine.requests[0].arguments.index("--services")
    assert tuple(
        second_engine.requests[0].arguments[service_index : service_index + 2]
    ) == ("--services", "iam")
    assert "-c" not in second_engine.requests[0].arguments
    assert "--compliance" not in second_engine.requests[0].arguments


def test_cross_provider_compliance_rejected_before_adapter_or_engine() -> None:
    """Provider/selector pairs are validated before credentials or CLI use."""
    lifecycle: list[str] = []
    engine = _Engine(b"[]", lifecycle)
    leases = _CredentialLeaseFactory(lifecycle)
    factory = ProwlerClientFactory(_EngineFactory(engine), leases)
    provider = AwsProviderInput(
        provider="aws",
        aws_access_key_id="access",
        aws_secret_access_key="secret",
        aws_account_id="123456789012",
        aws_region="eu-west-1",
    )

    with pytest.raises(ValueError, match="compliance selector"):
        factory.run(
            ProwlerConfig(),
            provider,
            compliance_selector=cast(Any, "cis_3.0_azure"),
        )

    assert leases.calls == []
    assert engine.requests == []
    assert lifecycle == []
