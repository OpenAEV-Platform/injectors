"""Raw pytest executable contract for CHK.017."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast, get_args

import pytest

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler._core.prowler_client import (
    AwsServiceSelector,
    AzureServiceSelector,
    ComplianceSelector,
    GcpServiceSelector,
)
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    ROUTE_CATALOG,
    AwsSelectComplianceContract,
    AwsSelectServiceContract,
    AzureSelectComplianceContract,
    AzureSelectServiceContract,
    ContractInputError,
    ContractInputIssue,
    GcpSelectComplianceContract,
    GcpSelectServiceContract,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig

from .conftest import AWS_FORM, AZURE_FORM, GCP_FORM

_PRE_EXISTING_25 = (
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
)
_SERVICE_ROUTES = (
    ("aws/select-service", "aws", "s3"),
    ("azure/select-service", "azure", "storage"),
    ("gcp/select-service", "gcp", "compute"),
)
_COMPLIANCE_ROUTES = (
    ("aws/select-compliance", "aws", "nis2_aws"),
    ("azure/select-compliance", "azure", "iso27001_2022_azure"),
    ("gcp/select-compliance", "gcp", "mitre_attack_gcp"),
)
_SELECT_ROUTES = _SERVICE_ROUTES + _COMPLIANCE_ROUTES
_FORMS = {"aws": AWS_FORM, "azure": AZURE_FORM, "gcp": GCP_FORM}
_SELECT_KEY = {
    "aws/select-service": "prowler_service",
    "aws/select-compliance": "prowler_compliance",
    "azure/select-service": "prowler_service",
    "azure/select-compliance": "prowler_compliance",
    "gcp/select-service": "prowler_service",
    "gcp/select-compliance": "prowler_compliance",
}
_EXPECTED_CLASS = {
    "aws/select-service": AwsSelectServiceContract,
    "aws/select-compliance": AwsSelectComplianceContract,
    "azure/select-service": AzureSelectServiceContract,
    "azure/select-compliance": AzureSelectComplianceContract,
    "gcp/select-service": GcpSelectServiceContract,
    "gcp/select-compliance": GcpSelectComplianceContract,
}
_SNAPSHOT_PATH = Path("/tmp/opencode/chk017-pre-change-contracts.json")  # noqa: S108
_ROUTE_IDS = [route for route, _, _ in _SELECT_ROUTES]


def _specification() -> ExecutionSpecification:
    """Build the immutable fake execution specification."""
    return ExecutionSpecification(
        executable="/fake/prowler",
        arguments=("/fake/prowler",),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        output=OutputSpecification(),
        timeout_seconds=30.0,
        maximum_accepted_output_bytes=1024,
    )


@dataclass
class _ClientFactory:
    """Record one fake CHK.004 client-factory call and return a fixed result."""

    result: CommandResult
    calls: list[tuple[Any, Any, tuple[str, ...], object, object]] = field(
        default_factory=list
    )

    def run(
        self,
        config: Any,
        provider: Any,
        *,
        check_filters: tuple[str, ...] = (),
        service_selector: object = None,
        compliance_selector: object = None,
    ) -> CommandResult:
        """Record the call exactly as the seam receives it."""
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


def _artifact(records: list[dict[str, Any]]) -> bytes:
    """Serialize the OCSF artifact bytes."""
    return json.dumps(records).encode()


def _contract(route_name: str) -> Any:
    """Resolve one shared registry instance by its stable route identity."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route_name)))


def _derived_values(route: str) -> tuple[str, ...]:
    """Return the derived choice values for one selectable route."""
    provider = route.split("/")[0]
    if route.endswith("select-service"):
        selector = {
            "aws": AwsServiceSelector,
            "azure": AzureServiceSelector,
            "gcp": GcpServiceSelector,
        }[provider]
        return get_args(selector)
    return tuple(
        value
        for value in get_args(ComplianceSelector)
        if value.endswith(f"_{provider}")
    )


@pytest.mark.parametrize(("route", "provider", "service"), _SERVICE_ROUTES)
def test_selectable_service_executes_chosen_service_once(
    route: str, provider: str, service: str, ocsf_record_factory: Any
) -> None:
    """Verify one parsed service selection drives exactly one seam call."""
    records = [
        ocsf_record_factory("First check", provider),
        ocsf_record_factory("Second check", provider),
    ]
    artifact = _artifact(records)
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[31mconsole noise is not JSON\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract(route)
    contract._client_factory = factory

    parsed = contract.parse_input({**_FORMS[provider], "prowler_service": service})
    outcome = contract.execute(ProwlerConfig(), parsed)

    assert len(factory.calls) == 1
    _config, provider_arg, check_filters, service_selector, compliance_selector = (
        factory.calls[0]
    )
    assert provider_arg == parsed
    assert check_filters == ()
    assert service_selector == service
    assert compliance_selector is None
    assert outcome.error is None
    assert len(outcome.findings) == 2
    assert outcome.raw_record_count == 2
    assert outcome.raw_output_bytes == len(artifact)
    assert tuple(f.finding_title for f in outcome.raw_preview) == (
        "First check",
        "Second check",
    )
    assert contract.safe_request_info(parsed)["filters"] == f"service={service}"
    trace = contract.render_trace(
        parsed,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )
    assert f"service={service}" in trace


@pytest.mark.parametrize(("route", "provider", "framework"), _COMPLIANCE_ROUTES)
def test_selectable_compliance_executes_chosen_framework_once(
    route: str, provider: str, framework: str, ocsf_record_factory: Any
) -> None:
    """Verify one parsed framework selection drives exactly one seam call."""
    records = [ocsf_record_factory("Framework check", provider)]
    artifact = _artifact(records)
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract(route)
    contract._client_factory = factory

    parsed = contract.parse_input({**_FORMS[provider], "prowler_compliance": framework})
    outcome = contract.execute(ProwlerConfig(), parsed)

    assert len(factory.calls) == 1
    _config, provider_arg, check_filters, service_selector, compliance_selector = (
        factory.calls[0]
    )
    assert provider_arg == parsed
    assert check_filters == ()
    assert service_selector is None
    assert compliance_selector == framework
    assert outcome.error is None
    assert len(outcome.findings) == 1
    assert outcome.raw_record_count == 1
    assert outcome.raw_output_bytes == len(artifact)
    assert contract.safe_request_info(parsed)["filters"] == f"compliance={framework}"
    trace = contract.render_trace(
        parsed,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )
    assert f"compliance={framework}" in trace


@pytest.mark.parametrize(
    ("route", "provider", "_value"), _SELECT_ROUTES, ids=_ROUTE_IDS
)
def test_select_field_is_closed_single_selection(
    route: str, provider: str, _value: str
) -> None:
    """Assert each serialized selectable contract declares one closed select."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id(route))
    )
    content = json.loads(str(item["contract_content"]))
    select_fields = [f for f in content["fields"] if f["type"] == "select"]
    assert len(select_fields) == 1
    select_field = select_fields[0]
    key = _SELECT_KEY[route]
    assert select_field["key"] == key
    assert select_field["mandatory"] is True
    assert select_field["cardinality"] == "1"
    derived = list(_derived_values(route))
    assert select_field["defaultValue"] == [derived[0]]
    assert list(select_field["choices"].keys()) == derived
    assert all(label for label in select_field["choices"].values())
    fixed = _contract(provider)
    provider_keys = tuple(f.key for f in fixed.build_provider_fields())
    actual_keys = tuple(f["key"] for f in content["fields"])
    assert actual_keys == (*provider_keys, key)
    assert content["manual"] is False
    assert {o["type"] for o in content["outputs"]} == {"text", "vulnerability"}
    assert all(route in o["labels"] for o in content["outputs"])


@pytest.mark.parametrize(
    ("route", "provider", "_value"), _SELECT_ROUTES, ids=_ROUTE_IDS
)
@pytest.mark.parametrize(
    "mutation", ("omit", "unknown_scalar", "empty_string", "empty_list", "null_value")
)
def test_missing_select_value_rejected_before_client(
    route: str, provider: str, _value: str, mutation: str
) -> None:
    """Assert empty required values and unknown scalars are rejected value-free."""
    key = _SELECT_KEY[route]
    form: dict[str, object] = dict(_FORMS[provider])
    if mutation == "unknown_scalar":
        form[key] = "select-canary-raw"
    elif mutation == "empty_string":
        form[key] = ""
    elif mutation == "empty_list":
        form[key] = []
    elif mutation == "null_value":
        form[key] = None
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory

    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)

    expected = (
        "select_unknown_value" if mutation == "unknown_scalar" else "select_missing"
    )
    assert excinfo.value.issues == (ContractInputIssue((key,), expected),)
    assert factory.calls == []
    assert "select-canary-raw" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("route", "provider", "_value"), _SELECT_ROUTES, ids=_ROUTE_IDS
)
def test_unknown_select_value_rejected_before_client(
    route: str, provider: str, _value: str
) -> None:
    """Assert closed-set violations are rejected value-free before any call."""
    key = _SELECT_KEY[route]
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract(route)
    contract._client_factory = factory
    derived = list(_derived_values(route))
    valid = derived[0]
    multiple = cast("list[object]", derived[:2])
    cases: list[tuple[list[object], str]] = [
        (["select-canary-unknown"], "select_unknown_value"),
        ([valid.upper()], "select_unknown_value"),
        ([f" {valid}"], "select_unknown_value"),
        ([f"{valid} "], "select_unknown_value"),
        ([""], "select_unknown_value"),
        ([123], "select_unknown_value"),
        ([None], "select_unknown_value"),
        (multiple, "select_multiple"),
    ]
    for submitted, expected_type in cases:
        form = {**_FORMS[provider], key: submitted}
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (ContractInputIssue((key,), expected_type),)
        message = str(excinfo.value)
        for element in submitted:
            if isinstance(element, str) and element.strip():
                assert element.strip() not in message
    assert factory.calls == []


@pytest.mark.parametrize(
    ("route", "provider", "_value"), _SELECT_ROUTES, ids=_ROUTE_IDS
)
def test_provider_field_rejection_unchanged(
    route: str, provider: str, _value: str
) -> None:
    """Assert provider-field rejection keeps the fixed contract structure."""
    key = _SELECT_KEY[route]
    other = next(p for p in _FORMS if p != provider)
    foreign_key = next(iter(_FORMS[other]))
    factory = _ClientFactory(CommandResult(specification=_specification()))
    selectable = _contract(route)
    selectable._client_factory = factory

    bad_form = {
        **_FORMS[provider],
        key: [_derived_values(route)[0]],
        foreign_key: "cross-provider-canary",
    }
    fixed = _contract(provider)
    with pytest.raises(ContractInputError) as fixed_error:
        fixed.parse_input({k: v for k, v in bad_form.items() if k != key})
    with pytest.raises(ContractInputError) as selectable_error:
        selectable.parse_input(bad_form)
    assert selectable_error.value.issues == fixed_error.value.issues
    assert "cross-provider-canary" not in str(selectable_error.value)

    both_invalid = {
        **_FORMS[provider],
        key: ["select-canary-bad"],
        foreign_key: "cross-provider-canary",
    }
    with pytest.raises(ContractInputError) as excinfo:
        selectable.parse_input(both_invalid)
    assert excinfo.value.issues == (ContractInputIssue((key,), "select_unknown_value"),)
    assert "cross-provider-canary" not in str(excinfo.value)

    provider_first = {
        **_FORMS[provider],
        key: ["select-canary-bad"],
        "provider": provider,
    }
    with pytest.raises(ContractInputError) as excinfo:
        selectable.parse_input(provider_first)
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )
    assert factory.calls == []


@pytest.mark.parametrize(
    ("route", "provider", "_value"), _SELECT_ROUTES, ids=_ROUTE_IDS
)
def test_choices_derived_from_selector_literals(
    route: str, provider: str, _value: str
) -> None:
    """Assert choices and parse acceptance equal the selector literals."""
    from prowler.contracts.selectable import (
        COMPLIANCE_SELECT_CHOICES,
        SERVICE_SELECT_CHOICES,
    )

    key = _SELECT_KEY[route]
    derived = list(_derived_values(route))
    if route.endswith("select-service"):
        offered = list(SERVICE_SELECT_CHOICES[provider].keys())
    else:
        offered = list(COMPLIANCE_SELECT_CHOICES[provider].keys())
    assert offered == derived
    contract = _contract(route)
    contract._client_factory = _ClientFactory(
        CommandResult(specification=_specification())
    )
    for value in derived:
        contract.parse_input({**_FORMS[provider], key: [value]})


def test_registry_admits_full_32_catalog_with_stable_identities() -> None:
    """Assert 32 routes are executable in canonical order with stable IDs."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    routes = tuple(r.route_name for r in ROUTE_CATALOG)
    assert len(serialized) == 32
    assert routes == _PRE_EXISTING_25 + (
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
    for item in serialized:
        route = next(
            r for r in routes if str(stable_contract_id(r)) == item["contract_id"]
        )
        contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(item["contract_id"]))
        assert contract.route_name == route
        assert contract.external_id == f"prowler:{route}"
        if route in _EXPECTED_CLASS:
            assert type(contract) is _EXPECTED_CLASS[route]
    assert len(set(routes)) == 32
    service_literals = (
        set(get_args(AwsServiceSelector))
        | set(get_args(AzureServiceSelector))
        | set(get_args(GcpServiceSelector))
    )
    assert "select-service" not in service_literals
    assert "select-compliance" not in {"aws", "azure", "gcp", "kubernetes"}
    _assert_pre_existing_25_unchanged(serialized)


def _assert_pre_existing_25_unchanged(serialized: list[dict[str, Any]]) -> None:
    """Compare the pre-existing 25 serialized contracts with the R08 snapshot."""
    assert (
        _SNAPSHOT_PATH.exists()
    ), "R08 pre-change snapshot is missing; regenerate it before running CHK.017 tests"
    snapshot = json.loads(_SNAPSHOT_PATH.read_text())
    assert len(snapshot) == 25
    by_id = {item["contract_id"]: item for item in serialized}
    for entry in snapshot:
        assert by_id[entry["contract_id"]] == entry


def test_failed_selectable_run_preserves_error_unchanged() -> None:
    """Assert a failed selectable run preserves the engine error exactly."""
    engine_error = RuntimeError("engine-failure-canary")
    failed = CommandResult(
        specification=_specification(),
        return_code=1,
        stdout=b"\x1b[31mboom\x1b[0m",
        stderr=b"stderr-canary",
        error=engine_error,
    )
    selectable = _contract("aws/select-service")
    selectable_factory = _ClientFactory(failed)
    selectable._client_factory = selectable_factory
    parsed = selectable.parse_input({**_FORMS["aws"], "prowler_service": ["iam"]})
    outcome = selectable.execute(ProwlerConfig(), parsed)

    fixed = _contract("aws/iam")
    fixed._client_factory = _ClientFactory(failed)
    fixed_parsed = fixed.parse_input(dict(_FORMS["aws"]))
    fixed_outcome = fixed.execute(ProwlerConfig(), fixed_parsed)

    assert len(selectable_factory.calls) == 1
    assert selectable_factory.calls[0][3] == "iam"
    assert selectable_factory.calls[0][4] is None
    assert outcome.error is engine_error
    assert outcome.findings == ()
    assert outcome.findings == fixed_outcome.findings
    trace = selectable.render_trace(
        None, (), 0, is_error=True, error_message=str(engine_error)
    )
    assert "service=unselected" in trace
    assert "iam" not in trace
