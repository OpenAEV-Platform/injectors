"""R05 selection-state checks for the selectable contracts."""

from __future__ import annotations

import threading
from collections.abc import Sequence

import pytest
from pydantic import SecretStr

from prowler._core.cli_engine import (
    CommandResult,
    ExecutionSpecification,
    OutputSpecification,
)
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    AwsSelectComplianceContract,
    AwsSelectServiceContract,
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AwsProviderInput


def _contract(route: str) -> BaseProwlerContract:
    """Resolve one shared registry instance by route name."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


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


class _RecordingFactory:
    """Record each seam call with its worker-thread identity."""

    def __init__(self) -> None:
        """Start with no recorded seam calls."""
        self.calls: list[tuple[int, object, object]] = []
        self._lock = threading.Lock()

    def run(
        self,
        config: object,
        provider: object,
        *,
        check_filters: Sequence[str] = (),
        service_selector: object = None,
        compliance_selector: object = None,
    ) -> CommandResult:
        """Record the selectors and return a failing, unmapped result."""
        with self._lock:
            self.calls.append(
                (threading.get_ident(), service_selector, compliance_selector)
            )
        return CommandResult(
            specification=_specification(),
            return_code=1,
            error=RuntimeError("recorded"),
        )


def test_selection_reset_at_parse_start(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the selection is reset at the start of every parse."""
    contract = _contract("aws/select-service")
    assert contract.safe_request_info(None)["filters"] == "service=unselected"
    parsed = contract.parse_input({**provider_forms["aws"], "prowler_service": ["s3"]})
    assert contract.safe_request_info(parsed)["filters"] == "service=s3"
    with pytest.raises(ContractInputError):
        contract.parse_input(dict(provider_forms["aws"]))
    assert contract.safe_request_info(None)["filters"] == "service=unselected"
    assert contract.safe_request_info(parsed)["filters"] == "service=unselected"
    second = contract.parse_input({**provider_forms["aws"], "prowler_service": ["ec2"]})
    assert contract.safe_request_info(second)["filters"] == "service=ec2"
    assert contract.safe_request_info(None)["filters"] == "service=unselected"


def test_failed_parse_never_exposes_prior_selection(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed parse never exposes a prior selection."""
    contract = _contract("aws/select-service")
    first = contract.parse_input({**provider_forms["aws"], "prowler_service": ["s3"]})
    assert contract.safe_request_info(first)["filters"] == "service=s3"
    with pytest.raises(ContractInputError):
        contract.parse_input(
            {**provider_forms["aws"], "prowler_service": ["nope-canary"]}
        )
    assert contract.safe_request_info(first)["filters"] == "service=unselected"
    assert contract.safe_request_info(None)["filters"] == "service=unselected"


def test_compliance_selection_state(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the compliance family holds and resets its selection."""
    contract = _contract("aws/select-compliance")
    assert contract.safe_request_info(None)["filters"] == "compliance=unselected"
    parsed = contract.parse_input(
        {**provider_forms["aws"], "prowler_compliance": ["nis2_aws"]}
    )
    assert contract.safe_request_info(parsed)["filters"] == "compliance=nis2_aws"
    with pytest.raises(ContractInputError):
        contract.parse_input({**provider_forms["aws"], "prowler_compliance": []})
    assert contract.safe_request_info(parsed)["filters"] == "compliance=unselected"


def test_fresh_instances_report_unselected_markers() -> None:
    """Assert fresh instances report the closed unselected markers."""
    assert (
        AwsSelectServiceContract().safe_request_info(None)["filters"]
        == "service=unselected"
    )
    assert (
        AwsSelectComplianceContract().safe_request_info(None)["filters"]
        == "compliance=unselected"
    )


def test_provider_key_rejection_clears_selection_before_early_return(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the provider-key early return clears the selection first."""
    contract = _contract("aws/select-service")
    parsed = contract.parse_input({**provider_forms["aws"], "prowler_service": ["s3"]})
    assert contract.safe_request_info(parsed)["filters"] == "service=s3"
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input({**provider_forms["aws"], "provider": "aws"})
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )
    assert contract.safe_request_info(None)["filters"] == "service=unselected"
    assert contract.safe_request_info(parsed)["filters"] == "service=unselected"


def test_each_worker_thread_executes_its_own_selection(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert two worker threads sharing one instance never cross selections."""
    forms = provider_forms["aws"]
    factory = _RecordingFactory()
    contract = AwsSelectServiceContract(factory)
    barrier = threading.Barrier(2)

    def _injection(service: str) -> None:
        parsed = contract.parse_input({**forms, "prowler_service": [service]})
        barrier.wait(timeout=5)
        contract.execute(ProwlerConfig(), parsed)

    first = threading.Thread(target=_injection, args=("s3",), name="worker-s3")
    second = threading.Thread(target=_injection, args=("ec2",), name="worker-ec2")
    first.start()
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()
    assert len(factory.calls) == 2
    selections = {ident: service for ident, service, _ in factory.calls}
    assert len(selections) == 2
    assert set(selections.values()) == {"s3", "ec2"}
    for _ident, _service, compliance in factory.calls:
        assert compliance is None


def test_failed_parse_in_one_thread_keeps_another_thread_run_intact(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed parse on one worker cannot corrupt another worker's run."""
    forms = provider_forms["aws"]
    factory = _RecordingFactory()
    contract = AwsSelectServiceContract(factory)
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def _healthy_run() -> None:
        outcomes["healthy_ident"] = threading.get_ident()
        parsed = contract.parse_input({**forms, "prowler_service": ["s3"]})
        barrier.wait(timeout=5)
        try:
            outcomes["healthy"] = contract.execute(ProwlerConfig(), parsed)
        except ValueError as error:
            outcomes["healthy"] = error

    def _broken_run() -> None:
        try:
            contract.parse_input({**forms, "prowler_service": ["nope-canary"]})
        except ContractInputError:
            pass
        barrier.wait(timeout=5)
        provider = AwsProviderInput(
            provider="aws",
            aws_access_key_id="AKIAEXAMPLEKEYID",
            aws_secret_access_key=SecretStr("example-secret"),
            aws_account_id="123456789012",
            aws_region="eu-west-1",
        )
        try:
            outcomes["broken"] = contract.execute(ProwlerConfig(), provider)
        except ValueError as error:
            outcomes["broken"] = error

    first = threading.Thread(target=_healthy_run, name="worker-s3")
    second = threading.Thread(target=_broken_run, name="worker-broken")
    first.start()
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()
    healthy = outcomes["healthy"]
    assert isinstance(healthy, ContractExecutionOutcome)
    broken = outcomes["broken"]
    assert isinstance(broken, ValueError)
    assert len(factory.calls) == 1
    ident, service, compliance = factory.calls[0]
    assert ident == outcomes["healthy_ident"]
    assert service == "s3"
    assert compliance is None
