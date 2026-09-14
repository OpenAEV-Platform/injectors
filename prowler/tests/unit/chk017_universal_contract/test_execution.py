"""R15 execution checks for the universal contract."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    BaseProwlerContract,
    UniversalProwlerContract,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AzureProviderInput


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
        check_filters: Sequence[str] = (),
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


def _record(title: str, provider: str) -> dict[str, Any]:
    """Build one minimal valid CHK.005 source record."""
    return {
        "finding_info": {
            "uid": f"check-{title}",
            "title": title,
            "desc": "Description",
        },
        "status": "New",
        "status_code": "PASS",
        "severity": "High",
        "resources": [{"uid": "asset-id", "name": "asset-name"}],
        "cloud": {
            "provider": provider,
            "region": "eu-west-1",
            "account": {"uid": "account-placeholder"},
        },
        "remediation": {"desc": "Remediate safely", "references": []},
    }


def _contract() -> BaseProwlerContract:
    """Resolve the shared universal registry instance."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))


@pytest.mark.parametrize(
    ("provider", "foreign"), (("aws", "azure"), ("kubernetes", "aws"))
)
def test_base_scope_runs_provider_base_once_and_filters_findings(
    provider: str,
    foreign: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert an empty-scope run calls the base seam once; preview stays unfiltered."""
    records = [
        _record("first-check", provider),
        _record("second-check", provider.upper()),
        _record("foreign-check", foreign),
    ]
    artifact = json.dumps(records).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[31mnoise\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    parsed = contract.parse_input(
        {**provider_forms[provider], "prowler_provider": [provider]}
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
    # Findings are filtered to the held provider; the raw preview is preserved
    # unfiltered (source order, all providers) exactly as the fixed base routes do.
    assert len(outcome.findings) == 2
    assert all(finding.cloud_provider == provider for finding in outcome.findings)
    assert tuple(f.finding_title for f in outcome.raw_preview) == (
        "first-check",
        "second-check",
        "foreign-check",
    )
    assert outcome.raw_record_count == 3
    assert outcome.raw_output_bytes == len(artifact)
    assert contract.safe_request_info(parsed)["filters"] == "base"
    assert contract.safe_request_info(parsed)["selected_provider"] == provider


@pytest.mark.parametrize(
    ("provider", "service_route", "service"),
    (
        ("aws", "aws/s3", "s3"),
        ("azure", "azure/storage", "storage"),
        ("gcp", "gcp/compute", "compute"),
    ),
)
def test_service_scope_runs_exactly_that_service_once(
    provider: str,
    service_route: str,
    service: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a service scope dispatches through the service seam once."""
    artifact = json.dumps(
        [_record("first-check", provider), _record("second-check", provider)]
    ).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    parsed = contract.parse_input(
        {
            **provider_forms[provider],
            "prowler_provider": [provider],
            "prowler_service": [service_route],
        }
    )
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
    assert contract.safe_request_info(parsed)["filters"] == f"service={service_route}"
    assert contract.safe_request_info(parsed)["selected_provider"] == provider


@pytest.mark.parametrize(
    ("provider", "route", "literal"),
    (
        ("kubernetes", "cis/kubernetes", "cis_1.12_kubernetes"),
        ("aws", "iso27001/aws", "iso27001_2022_aws"),
        ("gcp", "mitre/gcp", "mitre_attack_gcp"),
    ),
)
def test_compliance_scope_runs_exactly_that_framework_once(
    provider: str,
    route: str,
    literal: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a compliance scope dispatches through the compliance seam once."""
    artifact = json.dumps([_record("framework-check", provider)]).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    parsed = contract.parse_input(
        {
            **provider_forms[provider],
            "prowler_provider": [provider],
            "prowler_compliance": [route],
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
    assert compliance_selector == literal
    assert outcome.error is None
    assert len(outcome.findings) == 1
    assert outcome.raw_record_count == 1
    assert outcome.raw_output_bytes == len(artifact)
    assert contract.safe_request_info(parsed)["filters"] == f"compliance={route}"
    assert contract.safe_request_info(parsed)["selected_provider"] == provider


def test_execute_without_held_selection_raises_before_client_call(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert executing without a held parsed provider raises ValueError first."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    fresh = UniversalProwlerContract(factory)
    source = UniversalProwlerContract()
    parsed = source.parse_input({**provider_forms["aws"], "prowler_provider": ["aws"]})
    with pytest.raises(ValueError):
        fresh.execute(ProwlerConfig(), parsed)
    assert factory.calls == []


def test_execute_rejects_provider_model_that_mismatches_held_provider(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert execution rejects a provider model that mismatches the held one."""
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract = UniversalProwlerContract(factory)
    contract.parse_input({**provider_forms["aws"], "prowler_provider": ["aws"]})
    wrong = AzureProviderInput(
        provider="azure",
        azure_tenant_id="t",
        azure_client_id="c",
        azure_client_secret=SecretStr("s"),
        azure_subscription_id="sub",
        azure_provider="AzureCloud",
    )
    with pytest.raises(ValueError):
        contract.execute(ProwlerConfig(), wrong)
    assert factory.calls == []


def test_failed_run_preserves_error_and_empty_findings(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed universal run preserves the engine error and maps nothing."""
    engine_error = RuntimeError("engine-failure-canary")
    failed = CommandResult(
        specification=_specification(),
        return_code=1,
        stdout=b"boom",
        stderr=b"stderr",
        error=engine_error,
    )
    universal = _contract()
    universal._client_factory = _ClientFactory(failed)
    parsed = universal.parse_input(
        {
            **provider_forms["gcp"],
            "prowler_provider": ["gcp"],
            "prowler_service": ["gcp/compute"],
        }
    )
    outcome = universal.execute(ProwlerConfig(), parsed)
    assert outcome.error is engine_error
    assert outcome.findings == ()

    fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("gcp/compute")))
    fixed._client_factory = _ClientFactory(failed)
    fixed_parsed = fixed.parse_input(dict(provider_forms["gcp"]))
    fixed_outcome = fixed.execute(ProwlerConfig(), fixed_parsed)
    assert fixed_outcome.error is engine_error
    assert fixed_outcome.findings == outcome.findings


def test_success_preserves_raw_evidence_and_bounded_preview(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert raw counts and the ten-row preview boundary survive the mapping."""
    records = [_record(f"check-{index}", "aws") for index in range(12)]
    artifact = json.dumps(records).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract()
    contract._client_factory = factory
    parsed = contract.parse_input(
        {**provider_forms["aws"], "prowler_provider": ["aws"]}
    )
    outcome = contract.execute(ProwlerConfig(), parsed)
    assert outcome.error is None
    assert len(outcome.findings) == 12
    assert outcome.raw_record_count == 12
    assert outcome.raw_output_bytes == len(artifact)
    assert len(outcome.raw_preview) == 10
