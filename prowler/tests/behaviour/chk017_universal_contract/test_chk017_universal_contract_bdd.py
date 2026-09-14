"""Raw pytest executable contract for the CHK.017 universal contract."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    ROUTE_CATALOG,
    ContractInputError,
    ContractInputIssue,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig

from .conftest import PROVIDER_FORMS

PROVIDER_KEY = "prowler_provider"
SERVICE_KEY = "prowler_service"
COMPLIANCE_KEY = "prowler_compliance"
_SELECT_KEYS = (PROVIDER_KEY, SERVICE_KEY, COMPLIANCE_KEY)
_PRE_EXISTING_31 = (
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
    "aws/select-service",
    "aws/select-compliance",
    "azure/select-service",
    "azure/select-compliance",
    "gcp/select-service",
    "gcp/select-compliance",
)
_SELECT_TOKENS = ("select-service", "select-compliance")
_SNAPSHOT_PATH = Path(
    "/tmp/opencode/chk017-universal-pre-change-contracts.json"  # noqa: S108
)


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


def _expected_credential_fields() -> list[tuple[str, str, bool]]:
    """Derive the fifteen credential fields from the four fixed contracts."""
    expected: list[tuple[str, str, bool]] = []
    for provider in ("aws", "azure", "gcp", "kubernetes"):
        fixed = _contract(provider)
        for element in fixed.build_provider_fields():
            expected.append((provider, element.key, element.mandatory))
    return expected


def test_form_conditions_every_credential_field_on_provider_select() -> None:
    """Verify the serialized form conditions every credential field."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id("universal"))
    )
    content = json.loads(str(item["contract_content"]))
    fields = content["fields"]
    expected_credential = _expected_credential_fields()
    assert len(fields) == 18
    assert [f["key"] for f in fields] == [
        PROVIDER_KEY,
        *(key for _provider, key, _mandatory in expected_credential),
        SERVICE_KEY,
        COMPLIANCE_KEY,
    ]
    provider_select = fields[0]
    assert provider_select["type"] == "select"
    assert provider_select["mandatory"] is True
    assert provider_select["cardinality"] == "1"
    assert provider_select["defaultValue"] == ["aws"]
    assert provider_select["choices"] == {
        "aws": "AWS",
        "azure": "Azure",
        "gcp": "GCP",
        "kubernetes": "Kubernetes",
    }
    assert provider_select["visibleConditionFields"] == []
    assert provider_select["mandatoryConditionFields"] == []
    mandatory_count = 0
    for field_entry, (provider, _key, base_mandatory) in zip(
        fields[1:16], expected_credential, strict=True
    ):
        assert field_entry["visibleConditionFields"] == [PROVIDER_KEY]
        assert field_entry["visibleConditionValues"] == {PROVIDER_KEY: provider}
        assert field_entry["mandatory"] is False
        if base_mandatory:
            mandatory_count += 1
            assert field_entry["mandatoryConditionFields"] == [PROVIDER_KEY]
            assert field_entry["mandatoryConditionValues"] == {PROVIDER_KEY: provider}
        else:
            assert field_entry["mandatoryConditionFields"] == []
            assert field_entry["mandatoryConditionValues"] == {}
    assert mandatory_count == 13
    for select in (fields[16], fields[17]):
        assert select["type"] == "select"
        assert select["mandatory"] is False
        assert select["cardinality"] == "1"
        assert select["defaultValue"] == []
    assert len(fields[16]["choices"]) == 7
    assert len(fields[17]["choices"]) == 14
    assert {o["type"] for o in content["outputs"]} == {"text", "vulnerability"}
    assert {o["field"] for o in content["outputs"]} == {"findings", "vulnerabilities"}
    assert all(
        o["labels"] == ["prowler", "all", "universal"] for o in content["outputs"]
    )
    assert content["manual"] is False
    assert content["external_id"] == "prowler:universal"


@pytest.mark.parametrize("provider", ("aws", "kubernetes"))
def test_empty_scope_selects_run_provider_base_once(
    provider: str, ocsf_record_factory: Any
) -> None:
    """Verify an empty-scope run executes the provider base once and filters."""
    records = [
        ocsf_record_factory("First check", provider),
        ocsf_record_factory("Second check", provider.upper()),
        ocsf_record_factory("Foreign check", "azure" if provider != "azure" else "aws"),
    ]
    artifact = _artifact(records)
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[31mconsole noise is not JSON\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract("universal")
    contract._client_factory = factory

    parsed = contract.parse_input(
        {**PROVIDER_FORMS[provider], PROVIDER_KEY: [provider]}
    )
    outcome = contract.execute(ProwlerConfig(), parsed)

    assert len(factory.calls) == 1
    _config, provider_arg, check_filters, service_selector, compliance_selector = (
        factory.calls[0]
    )
    assert provider_arg == parsed
    assert check_filters == ()
    assert service_selector is None
    assert compliance_selector is None
    assert outcome.error is None
    assert len(outcome.findings) == 2
    assert all(finding.cloud_provider == provider for finding in outcome.findings)
    assert outcome.raw_record_count == 3
    assert outcome.raw_output_bytes == len(artifact)
    info = contract.safe_request_info(parsed)
    assert info["filters"] == "base"
    assert info["selected_provider"] == provider
    trace = contract.render_trace(
        parsed,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )
    assert f"provider: {provider}" in trace
    assert "filters: base" in trace
    assert f"selected_provider: {provider}" in trace


def test_service_scope_runs_exactly_that_service_once(ocsf_record_factory: Any) -> None:
    """Verify a service scope dispatches exactly that service once."""
    records = [
        ocsf_record_factory("First check", "aws"),
        ocsf_record_factory("Second check", "aws"),
    ]
    artifact = _artifact(records)
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract("universal")
    contract._client_factory = factory

    parsed = contract.parse_input(
        {
            **PROVIDER_FORMS["aws"],
            PROVIDER_KEY: ["aws"],
            SERVICE_KEY: ["aws/s3"],
        }
    )
    outcome = contract.execute(ProwlerConfig(), parsed)

    assert len(factory.calls) == 1
    _config, provider_arg, check_filters, service_selector, compliance_selector = (
        factory.calls[0]
    )
    assert provider_arg == parsed
    assert check_filters == ()
    assert service_selector == "s3"
    assert compliance_selector is None
    assert outcome.error is None
    assert len(outcome.findings) == 2
    info = contract.safe_request_info(parsed)
    assert info["filters"] == "service=aws/s3"
    assert info["selected_provider"] == "aws"
    trace = contract.render_trace(
        parsed,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )
    assert "service=aws/s3" in trace
    assert "provider: aws" in trace


def test_compliance_scope_runs_exactly_that_framework_once(
    ocsf_record_factory: Any,
) -> None:
    """Verify a compliance scope dispatches exactly that framework once."""
    records = [ocsf_record_factory("Framework check", "kubernetes")]
    artifact = _artifact(records)
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract("universal")
    contract._client_factory = factory

    parsed = contract.parse_input(
        {
            **PROVIDER_FORMS["kubernetes"],
            PROVIDER_KEY: ["kubernetes"],
            COMPLIANCE_KEY: ["cis/kubernetes"],
        }
    )
    outcome = contract.execute(ProwlerConfig(), parsed)

    assert len(factory.calls) == 1
    _config, provider_arg, check_filters, service_selector, compliance_selector = (
        factory.calls[0]
    )
    assert provider_arg == parsed
    assert check_filters == ()
    assert service_selector is None
    assert compliance_selector == "cis_1.12_kubernetes"
    assert outcome.error is None
    assert len(outcome.findings) == 1
    info = contract.safe_request_info(parsed)
    assert info["filters"] == "compliance=cis/kubernetes"
    assert info["selected_provider"] == "kubernetes"
    trace = contract.render_trace(
        parsed,
        outcome.findings,
        1,
        raw_record_count=outcome.raw_record_count,
        raw_output_bytes=outcome.raw_output_bytes,
        raw_preview=outcome.raw_preview,
    )
    assert "compliance=cis/kubernetes" in trace
    assert "provider: kubernetes" in trace


def test_both_scope_selects_rejected_before_any_client_call() -> None:
    """Verify both scope selects set is one closed conflict before any call."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract("universal")
    contract._client_factory = factory
    form = {
        **PROVIDER_FORMS["gcp"],
        PROVIDER_KEY: ["gcp"],
        SERVICE_KEY: ["gcp/iam"],
        COMPLIANCE_KEY: ["iso27001/gcp"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEY, COMPLIANCE_KEY), "scope_conflict"),
    )
    message = str(excinfo.value)
    assert "gcp/iam" not in message
    assert "iso27001/gcp" not in message
    assert factory.calls == []


def test_scope_provider_mismatch_rejected_before_any_client_call() -> None:
    """Verify a scope whose provider disagrees is rejected value-free."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract("universal")
    contract._client_factory = factory
    service_mismatch = {
        **PROVIDER_FORMS["azure"],
        PROVIDER_KEY: ["azure"],
        SERVICE_KEY: ["aws/iam"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(service_mismatch)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEY,), "scope_provider_mismatch"),
    )
    assert "aws/iam" not in str(excinfo.value)
    compliance_mismatch = {
        **PROVIDER_FORMS["azure"],
        PROVIDER_KEY: ["azure"],
        COMPLIANCE_KEY: ["mitre/aws"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(compliance_mismatch)
    assert excinfo.value.issues == (
        ContractInputIssue((COMPLIANCE_KEY,), "scope_provider_mismatch"),
    )
    assert "mitre/aws" not in str(excinfo.value)
    assert factory.calls == []


def test_wrong_provider_fields_cannot_satisfy_selected_provider() -> None:
    """Verify foreign fields are ignored while the selected provider's fail."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    universal = _contract("universal")
    universal._client_factory = factory
    form = {**PROVIDER_FORMS["azure"], PROVIDER_KEY: ["aws"]}
    with pytest.raises(ContractInputError) as universal_error:
        universal.parse_input(form)
    fixed = _contract("aws")
    with pytest.raises(ContractInputError) as fixed_error:
        fixed.parse_input({})
    assert universal_error.value.issues == fixed_error.value.issues
    for key in PROVIDER_FORMS["azure"]:
        assert not any(key in issue.location for issue in universal_error.value.issues)
    assert "tenant-id" not in str(universal_error.value)
    assert factory.calls == []


def test_missing_provider_select_rejected_before_any_client_call() -> None:
    """Verify a missing provider select is rejected value-free and closed."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = _contract("universal")
    contract._client_factory = factory
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(dict(PROVIDER_FORMS["aws"]))
    assert excinfo.value.issues == (
        ContractInputIssue((PROVIDER_KEY,), "select_missing"),
    )
    assert factory.calls == []
    provider_first = {
        **PROVIDER_FORMS["aws"],
        PROVIDER_KEY: ["provider-canary-bad"],
        "provider": "aws",
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(provider_first)
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )
    assert "provider-canary-bad" not in str(excinfo.value)
    assert factory.calls == []


def test_failed_universal_run_preserves_error_unchanged() -> None:
    """Verify a failed universal run forwards the closed error and held provider."""
    engine_error = RuntimeError("engine-failure-canary")
    failed = CommandResult(
        specification=_specification(),
        return_code=1,
        stdout=b"\x1b[31mboom\x1b[0m",
        stderr=b"stderr-canary",
        error=engine_error,
    )
    universal = _contract("universal")
    universal_factory = _ClientFactory(failed)
    universal._client_factory = universal_factory
    parsed = universal.parse_input(
        {
            **PROVIDER_FORMS["gcp"],
            PROVIDER_KEY: ["gcp"],
            SERVICE_KEY: ["gcp/compute"],
        }
    )
    outcome = universal.execute(ProwlerConfig(), parsed)

    fixed = _contract("gcp/compute")
    fixed._client_factory = _ClientFactory(failed)
    fixed_parsed = fixed.parse_input(dict(PROVIDER_FORMS["gcp"]))
    fixed_outcome = fixed.execute(ProwlerConfig(), fixed_parsed)

    assert len(universal_factory.calls) == 1
    assert universal_factory.calls[0][3] == "compute"
    assert universal_factory.calls[0][4] is None
    assert outcome.error is engine_error
    assert outcome.findings == ()
    assert outcome.findings == fixed_outcome.findings
    error_message = str(engine_error)
    trace = universal.render_trace(
        None, (), 0, is_error=True, error_message=error_message
    )
    fixed_trace = fixed.render_trace(
        None, (), 0, is_error=True, error_message=error_message
    )
    # Parity with the fixed route: the closed error channel is forwarded, not blanked.
    assert error_message in trace
    assert error_message in fixed_trace
    # The held provider is reported on the failure path, never the all meta-token.
    assert "provider: gcp" in trace
    assert "provider: gcp" in fixed_trace
    # The held scope stays hidden on the failure path (closed markers only).
    assert "filters: unselected" in trace
    assert "selected_provider: unselected" in trace
    assert "gcp/compute" not in trace


def test_registry_admits_full_32_catalog_with_stable_identities() -> None:
    """Verify 32 routes are executable with stable identities and 31 unchanged."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    routes = tuple(r.route_name for r in ROUTE_CATALOG)
    assert len(serialized) == 32
    assert routes == _PRE_EXISTING_31 + ("universal",)
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
    assert "/" not in "universal"
    assert "universal" not in {"aws", "azure", "gcp", "kubernetes"}
    assert "all" not in {"aws", "azure", "gcp", "kubernetes"}
    for existing in _PRE_EXISTING_31:
        assert "all" not in existing.split("/")
    _assert_pre_existing_31_unchanged(serialized)


def _assert_pre_existing_31_unchanged(serialized: list[dict[str, Any]]) -> None:
    """Compare the pre-existing 31 serialized contracts with the R18 snapshot."""
    assert (
        _SNAPSHOT_PATH.exists()
    ), "R18 pre-change snapshot is missing; regenerate it before running this suite"
    snapshot = json.loads(_SNAPSHOT_PATH.read_text())
    assert len(snapshot) == 31
    by_id = {item["contract_id"]: item for item in serialized}
    for entry in snapshot:
        assert by_id[entry["contract_id"]] == entry


def test_scope_choices_derived_from_selector_literals() -> None:
    """Verify the drift guard in both directions against the catalog."""
    from prowler.contracts.universal import (
        COMPLIANCE_SCOPE_OPTIONS,
        SERVICE_SCOPE_OPTIONS,
    )

    service_routes = tuple(
        route.route_name
        for route in ROUTE_CATALOG
        if route.family == "service" and not route.route_name.endswith(_SELECT_TOKENS)
    )
    compliance_routes = tuple(
        route.route_name
        for route in ROUTE_CATALOG
        if route.family == "compliance"
        and not route.route_name.endswith(_SELECT_TOKENS)
    )
    assert len(service_routes) == 7
    assert len(compliance_routes) == 14
    assert tuple(option.route for option in SERVICE_SCOPE_OPTIONS) == service_routes
    assert (
        tuple(option.route for option in COMPLIANCE_SCOPE_OPTIONS) == compliance_routes
    )
    assert "kubernetes" not in {option.provider for option in SERVICE_SCOPE_OPTIONS}
    kube_routes = {
        option.route
        for option in COMPLIANCE_SCOPE_OPTIONS
        if option.provider == "kubernetes"
    }
    assert kube_routes == {"cis/kubernetes", "iso27001/kubernetes"}
    for option in SERVICE_SCOPE_OPTIONS:
        fixed = _contract(option.route)
        assert fixed.service_selector == option.literal
    for option in COMPLIANCE_SCOPE_OPTIONS:
        fixed = _contract(option.route)
        assert fixed.compliance_selector == option.literal
    routes = [
        option.route for option in (*SERVICE_SCOPE_OPTIONS, *COMPLIANCE_SCOPE_OPTIONS)
    ]
    assert len(routes) == len(set(routes))
