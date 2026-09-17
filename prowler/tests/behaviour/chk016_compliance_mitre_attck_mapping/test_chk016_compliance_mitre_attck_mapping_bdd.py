"""Raw pytest executable contract for CHK.016."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast, get_args

import pytest
from pydantic import SecretStr
from pyoaev.configuration import ConfigLoaderOAEV

from prowler._core.cli_engine import (CommandResult, ExecutionSpecification,
                                      OutputSpecification,
                                      ValidatedCommandRequest)
from prowler._core.prowler_client import (OUTPUT_ARTIFACT_FILENAME,
                                          ProwlerClientFactory)
from prowler.contracts import (DEFAULT_PROWLER_CONTRACTS, ROUTE_CATALOG,
                               stable_contract_id)
from prowler.models.configs.config_loader import (ConfigLoader, InjectorConfig,
                                                  ProwlerConfig)
from prowler.models.findings import OpenAevFinding
from prowler.models.provider_inputs import AwsProviderInput

from .conftest import RecordingLogger

_MITRE_ROUTES = (
    ("mitre/aws", "aws", "mitre_attack_aws"),
    ("mitre/azure", "azure", "mitre_attack_azure"),
    ("mitre/gcp", "gcp", "mitre_attack_gcp"),
)
_FINAL_ROUTE_EXPECTATIONS = (
    ("aws", "aws", None, None),
    ("azure", "azure", None, None),
    ("gcp", "gcp", None, None),
    ("kubernetes", "kubernetes", None, None),
    ("aws/iam", "aws", "iam", None),
    ("aws/s3", "aws", "s3", None),
    ("aws/ec2", "aws", "ec2", None),
    ("azure/iam", "azure", "iam", None),
    ("azure/storage", "azure", "storage", None),
    ("gcp/iam", "gcp", "iam", None),
    ("gcp/compute", "gcp", "compute", None),
    ("cis/aws", "aws", None, "cis_3.0_aws"),
    ("cis/azure", "azure", None, "cis_3.0_azure"),
    ("cis/gcp", "gcp", None, "cis_3.0_gcp"),
    ("cis/kubernetes", "kubernetes", None, "cis_1.12_kubernetes"),
    ("nis2/aws", "aws", None, "nis2_aws"),
    ("nis2/azure", "azure", None, "nis2_azure"),
    ("nis2/gcp", "gcp", None, "nis2_gcp"),
    ("iso27001/aws", "aws", None, "iso27001_2022_aws"),
    ("iso27001/azure", "azure", None, "iso27001_2022_azure"),
    ("iso27001/gcp", "gcp", None, "iso27001_2022_gcp"),
    (
        "iso27001/kubernetes",
        "kubernetes",
        None,
        "iso27001_2022_kubernetes",
    ),
    *((route, provider, None, selector) for route, provider, selector in _MITRE_ROUTES),
)
_COMPLIANCE_SELECTORS = tuple(
    selector for _, _, _, selector in _FINAL_ROUTE_EXPECTATIONS if selector is not None
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


def test_final_registry_serializes_and_resolves_exactly_32_canonical_routes() -> None:
    """Every canonical descriptor has one executable stable registry entry."""
    expected_routes = tuple(item[0] for item in _FINAL_ROUTE_EXPECTATIONS) + (
        "aws/select-service",
        "aws/select-compliance",
        "azure/select-service",
        "azure/select-compliance",
        "gcp/select-service",
        "gcp/select-compliance",
        "universal",
    )
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()

    assert tuple(route.route_name for route in ROUTE_CATALOG) == expected_routes
    assert len(serialized) == 32
    assert tuple(item["contract_id"] for item in serialized) == tuple(
        str(stable_contract_id(route)) for route in expected_routes
    )
    for route, provider_name, _, _ in _FINAL_ROUTE_EXPECTATIONS:
        contract = _contract(route)
        content = json.loads(
            next(
                item["contract_content"]
                for item in serialized
                if item["contract_id"] == contract.contract_id
            )
        )
        assert contract.route_name == route
        assert contract.provider == provider_name
        assert contract.family == next(
            descriptor.family
            for descriptor in ROUTE_CATALOG
            if descriptor.route_name == route
        )
        assert content["external_id"] == f"prowler:{route}"
        assert content["contract_id"] == str(stable_contract_id(route))


def test_mitre_serialization_has_provider_fields_shared_outputs_and_no_selector() -> (
    None
):
    """MITRE routes expose no user-controlled selector or invented report output."""
    serialized = {
        item["contract_id"]: item for item in DEFAULT_PROWLER_CONTRACTS.contracts()
    }

    for route, provider_name, _ in _MITRE_ROUTES:
        item = serialized[str(stable_contract_id(route))]
        content = json.loads(item["contract_content"])
        keys = tuple(field["key"] for field in content["fields"])
        assert keys == tuple(
            field.key for field in _contract(provider_name).build_provider_fields()
        )
        assert all(
            token not in key
            for key in keys
            for token in ("compliance", "framework", "selector")
        )
        assert tuple(
            (output["type"], output["field"]) for output in content["outputs"]
        ) == (("text", "findings"), ("vulnerability", "vulnerabilities"))
        assert all(route in output["labels"] for output in content["outputs"])
        assert provider_name in content["label"]["en"].casefold()


def test_compliance_selector_type_contains_exact_final_values() -> None:
    """The internal seam admits only the 14 route-owned compliance values."""
    import prowler._core.prowler_client as client_api

    selector_type = client_api.__dict__.get("ComplianceSelector")

    assert selector_type is not None
    assert get_args(selector_type) == _COMPLIANCE_SELECTORS


@pytest.mark.parametrize(("route", "provider_name", "compliance"), _MITRE_ROUTES)
def test_mitre_route_selects_exact_typed_compliance_once(
    route: str,
    provider_name: str,
    compliance: str,
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """A fixed selector crosses the existing compliance seam exactly once."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory

    contract.execute(
        ProwlerConfig(), contract.parse_input(provider_forms[provider_name])
    )

    assert len(factory.calls) == 1
    assert factory.calls[0][2:] == ((), None, compliance)


def test_unsupported_mitre_contract_metadata_is_rejected_pre_client(
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """A provider/selector mismatch cannot consume the CHK.004 seam."""
    import prowler.contracts as contract_api

    mitre_contract = contract_api.__dict__.get("MitreComplianceContract")
    assert mitre_contract is not None

    class InvalidMitreContract(mitre_contract):
        contract_id = str(stable_contract_id("mitre/aws"))
        external_id = "prowler:mitre/aws"
        route_name = "mitre/aws"
        provider = "aws"
        label = "Invalid"
        compliance_selector = "mitre_attack_azure"

    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = InvalidMitreContract(factory)

    with pytest.raises(ValueError, match="unsupported MITRE compliance selection"):
        contract.execute(ProwlerConfig(), contract.parse_input(provider_forms["aws"]))

    assert factory.calls == []


def test_mapping_preserves_mitre_values_duplicates_outputs_and_dynamic_trace(
    provider_forms: dict[str, dict[str, object]], mitre_ocsf_record_factory: Any
) -> None:
    """Existing CHK.005 findings alone feed all three presentation channels."""
    duplicate = mitre_ocsf_record_factory(
        "duplicate",
        compliance=("MITRE ATT&CK", "T1078", "T1078", "CIS 1.1"),
    )
    records = [
        mitre_ocsf_record_factory(
            "first",
            status="PASS",
            compliance=("MITRE ATT&CK", "T1190", "ISO27001 A.5.1"),
        ),
        duplicate,
        duplicate.copy(),
        mitre_ocsf_record_factory("excluded", provider="azure"),
        mitre_ocsf_record_factory(
            "last", status="PASS", compliance=("MITRE ATT&CK", "T1530")
        ),
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
    contract = _contract("mitre/aws")
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

    expected_names = ("first", "duplicate", "duplicate", "last")
    expected_tags = (
        ("MITRE ATT&CK", "T1190", "ISO27001 A.5.1"),
        ("MITRE ATT&CK", "T1078", "T1078", "CIS 1.1"),
        ("MITRE ATT&CK", "T1078", "T1078", "CIS 1.1"),
        ("MITRE ATT&CK", "T1530"),
    )
    assert tuple(OpenAevFinding.model_fields) == (
        "type",
        "value",
        "expectation_result",
        "severity",
        "severity_weight",
        "asset_reference",
        "asset_name",
        "cloud_provider",
        "region",
        "cloud_account",
        "compliance_tags",
        "remediation",
        "remediation_url",
        "description",
    )
    assert tuple(item.value for item in outcome.findings) == expected_names
    assert tuple(item.compliance_tags for item in outcome.findings) == expected_tags
    assert tuple(json.loads(item) for item in payload["findings"]) == tuple(
        item.model_dump(mode="json") for item in outcome.findings
    )
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
        tuple(
            next(name for name in expected_names if name in line)
            for line in rendered_rows
        )
        == expected_names
    )
    assert tuple(payload) == ("findings", "vulnerabilities")
    assert "excluded" not in trace[:raw_section_index]
    assert trace.index("Prowler Findings") < raw_section_index
    assert outcome.raw_record_count == 5
    assert outcome.raw_output_bytes == len(artifact)
    assert "mitre/aws" in trace
    assert "compliance=mitre_attack_aws" in trace


def test_mapping_emits_only_enabled_boolean_compliance_tags(
    provider_forms: dict[str, dict[str, object]], mitre_ocsf_record_factory: Any
) -> None:
    """Boolean mapping values become tags only when explicitly enabled."""
    record = mitre_ocsf_record_factory(
        "boolean-mapping",
        compliance={
            "MITRE ATT&CK": True,
            "CIS 1.1": True,
            "ISO27001": False,
        },
    )
    factory = _ClientFactory(
        CommandResult(
            specification=_specification(),
            return_code=0,
            stdout=b"console output is not OCSF JSON",
            parsed=json.dumps([record]).encode(),
        )
    )
    contract = _contract("mitre/aws")
    contract._client_factory = factory

    outcome = contract.execute(
        ProwlerConfig(), contract.parse_input(provider_forms["aws"])
    )

    assert outcome.findings[0].compliance_tags == ("MITRE ATT&CK", "CIS 1.1")


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


@pytest.mark.parametrize(
    ("route", "provider_name", "service", "compliance"),
    _FINAL_ROUTE_EXPECTATIONS,
)
def test_final_25_contracts_resolve_and_dispatch_once_through_runtime(
    route: str,
    provider_name: str,
    service: str | None,
    compliance: str | None,
    provider_forms: dict[str, dict[str, object]],
) -> None:
    """The final registry runtime-resolves every route to one expected client call."""
    from prowler.injector import ProwlerInjector

    factory = _ClientFactory(
        CommandResult(
            specification=_specification(),
            return_code=0,
            stdout=b"console output is not OCSF JSON",
            parsed=b"[]",
        )
    )
    contract = _contract(route)
    contract._client_factory = factory
    helper = _Helper()
    message = {
        "injection": {
            "inject_id": f"inject-{route}",
            "injector_contract_id": str(stable_contract_id(route)),
            "inject_content": provider_forms[provider_name],
        }
    }

    ProwlerInjector(_config(), helper).process_message(message)

    assert len(factory.calls) == 1
    assert factory.calls[0][2:] == ((), service, compliance)
    assert helper.api.inject.events[1][2]["execution_status"] == "SUCCESS"


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


@pytest.mark.parametrize(("route", "provider_name", "compliance"), _MITRE_ROUTES)
def test_mitre_runtime_lifecycle_logs_and_canaries(
    route: str,
    provider_name: str,
    compliance: str,
    provider_forms: dict[str, dict[str, object]],
    mitre_ocsf_record_factory: Any,
) -> None:
    """MITRE runtime logs safe lifecycle metadata for every owned provider."""
    from prowler.injector import ProwlerInjector

    callback_name = f"CALLBACK-CANARY-{provider_name}"
    finding_name = f"FINDING-CANARY-{provider_name}"
    records = [
        mitre_ocsf_record_factory(callback_name, provider=provider_name, status="PASS"),
        mitre_ocsf_record_factory(finding_name, provider=provider_name),
        mitre_ocsf_record_factory("excluded", provider="unsupported"),
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
    environment_keys = tuple(key for key, _ in engine.requests[0].environment)
    expected_environment_keys = {
        "aws": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"),
        "azure": ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"),
        "gcp": (),
    }
    assert environment_keys == expected_environment_keys[provider_name]
    if provider_name == "gcp":
        assert lifecycle == ["create:.json", "engine", "cleanup"]
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
        else ["create:.json", "engine", "cleanup"]
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


def test_cross_provider_mitre_is_rejected_before_adapter_or_engine() -> None:
    """A mismatched internal selector cannot consume credentials or runtime."""
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
            compliance_selector=cast(Any, "mitre_attack_azure"),
        )

    assert leases.calls == []
    assert engine.requests == []
    assert lifecycle == []
