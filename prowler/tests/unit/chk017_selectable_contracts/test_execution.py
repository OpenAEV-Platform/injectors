"""R04 execution checks for the selectable contracts."""

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
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AzureProviderInput, GcpProviderInput


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


def _contract(route: str) -> BaseProwlerContract:
    """Resolve one shared registry instance by route name."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


@pytest.mark.parametrize(
    ("route", "provider", "service"),
    (
        ("aws/select-service", "aws", "s3"),
        ("azure/select-service", "azure", "storage"),
        ("gcp/select-service", "gcp", "compute"),
    ),
)
def test_service_execution_one_call_and_mapping(
    route: str,
    provider: str,
    service: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert service execution performs one mapped seam call."""
    artifact = json.dumps(
        [_record("first-check", provider), _record("second-check", provider)]
    ).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"\x1b[31mnoise\x1b[0m",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract(route)
    contract._client_factory = factory
    parsed = contract.parse_input(
        {**provider_forms[provider], "prowler_service": [service]}
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
    assert tuple(f.finding_title for f in outcome.raw_preview) == (
        "first-check",
        "second-check",
    )
    assert outcome.raw_record_count == 2
    assert outcome.raw_output_bytes == len(artifact)


@pytest.mark.parametrize(
    ("route", "provider", "framework"),
    (
        ("aws/select-compliance", "aws", "nis2_aws"),
        ("azure/select-compliance", "azure", "iso27001_2022_azure"),
        ("gcp/select-compliance", "gcp", "mitre_attack_gcp"),
    ),
)
def test_compliance_execution_one_call_and_mapping(
    route: str,
    provider: str,
    framework: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert compliance execution performs one mapped seam call."""
    artifact = json.dumps([_record("framework-check", provider)]).encode()
    result = CommandResult(
        specification=_specification(),
        return_code=0,
        stdout=b"",
        parsed=artifact,
    )
    factory = _ClientFactory(result)
    contract = _contract(route)
    contract._client_factory = factory
    parsed = contract.parse_input(
        {**provider_forms[provider], "prowler_compliance": [framework]}
    )
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


def test_execute_without_held_selection_raises_value_error(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert executing without a held selection raises ValueError."""
    contract = _contract("aws/select-service")
    factory = _ClientFactory(CommandResult(specification=_specification()))
    contract._client_factory = factory
    with pytest.raises(ValueError):
        # Raw form dict on purpose: the guard must reject non-provider input.
        contract.execute(ProwlerConfig(), provider_forms["aws"])  # type: ignore[arg-type]
    assert factory.calls == []


def test_service_execution_rejects_wrong_provider(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert service execution rejects a non-matching provider input."""
    contract = _contract("aws/select-service")
    contract._client_factory = _ClientFactory(
        CommandResult(specification=_specification())
    )
    contract.parse_input({**provider_forms["aws"], "prowler_service": ["iam"]})
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


def test_compliance_execution_rejects_wrong_provider(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert compliance execution rejects a non-matching provider input."""
    contract = _contract("azure/select-compliance")
    contract._client_factory = _ClientFactory(
        CommandResult(specification=_specification())
    )
    contract.parse_input(
        {**provider_forms["azure"], "prowler_compliance": ["cis_3.0_azure"]}
    )
    wrong = GcpProviderInput(
        provider="gcp",
        gcp_service_account_json=SecretStr('{"type": "service_account"}'),
        gcp_project_id="project-id",
    )
    with pytest.raises(ValueError):
        contract.execute(ProwlerConfig(), wrong)


def test_failed_run_preserves_error_and_empty_findings(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed run preserves the engine error and maps nothing."""
    engine_error = RuntimeError("engine-failure-canary")
    failed = CommandResult(
        specification=_specification(),
        return_code=1,
        stdout=b"boom",
        stderr=b"stderr",
        error=engine_error,
    )
    selectable = _contract("aws/select-service")
    selectable._client_factory = _ClientFactory(failed)
    parsed = selectable.parse_input(
        {**provider_forms["aws"], "prowler_service": ["iam"]}
    )
    outcome = selectable.execute(ProwlerConfig(), parsed)
    assert outcome.error is engine_error
    assert outcome.findings == ()

    fixed = _contract("aws/iam")
    fixed._client_factory = _ClientFactory(failed)
    fixed_parsed = fixed.parse_input(dict(provider_forms["aws"]))
    fixed_outcome = fixed.execute(ProwlerConfig(), fixed_parsed)
    assert fixed_outcome.error is engine_error
    assert fixed_outcome.findings == ()
