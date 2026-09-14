"""R16 selection-state checks for the universal contract."""

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
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    UniversalProwlerContract,
    stable_contract_id,
)
from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import AzureProviderInput


def _contract() -> BaseProwlerContract:
    """Resolve the shared universal registry instance."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))


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
        self.calls: list[tuple[int, object, object, object]] = []
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
        """Record the thread, provider name, and selectors; fail unambiguously."""
        with self._lock:
            self.calls.append(
                (
                    threading.get_ident(),
                    getattr(provider, "provider", None),
                    service_selector,
                    compliance_selector,
                )
            )
        return CommandResult(
            specification=_specification(),
            return_code=1,
            error=RuntimeError("recorded"),
        )


def test_selection_reset_at_parse_start(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert all three held values reset at the start of every parse."""
    contract = _contract()
    assert contract.safe_request_info(None)["filters"] == "unselected"
    assert contract.safe_request_info(None)["selected_provider"] == "unselected"
    parsed = contract.parse_input(
        {**provider_forms["aws"], "prowler_provider": ["aws"]}
    )
    assert contract.safe_request_info(parsed)["filters"] == "base"
    assert contract.safe_request_info(parsed)["selected_provider"] == "aws"
    with pytest.raises(ContractInputError):
        contract.parse_input(dict(provider_forms["aws"]))
    assert contract.safe_request_info(None)["filters"] == "unselected"
    assert contract.safe_request_info(None)["selected_provider"] == "unselected"
    assert contract.safe_request_info(parsed)["filters"] == "unselected"
    assert contract.safe_request_info(parsed)["selected_provider"] == "unselected"
    second = contract.parse_input(
        {
            **provider_forms["aws"],
            "prowler_provider": ["aws"],
            "prowler_service": ["aws/s3"],
        }
    )
    assert contract.safe_request_info(second)["filters"] == "service=aws/s3"
    assert contract.safe_request_info(second)["selected_provider"] == "aws"
    assert contract.safe_request_info(None)["filters"] == "unselected"
    assert contract.safe_request_info(None)["selected_provider"] == "unselected"


def test_failed_parse_never_exposes_prior_selection(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed parse never exposes a prior selection on a reused thread."""
    contract = _contract()
    parsed = contract.parse_input(
        {
            **provider_forms["aws"],
            "prowler_provider": ["aws"],
            "prowler_service": ["aws/s3"],
        }
    )
    assert contract.safe_request_info(parsed)["filters"] == "service=aws/s3"
    with pytest.raises(ContractInputError):
        contract.parse_input(
            {
                **provider_forms["aws"],
                "prowler_provider": ["aws"],
                "prowler_service": ["scope-canary-bad"],
            }
        )
    assert contract.safe_request_info(parsed)["filters"] == "unselected"
    assert contract.safe_request_info(parsed)["selected_provider"] == "unselected"
    assert contract.safe_request_info(None)["filters"] == "unselected"
    assert contract.safe_request_info(None)["selected_provider"] == "unselected"


def test_fresh_instance_reports_unselected_markers() -> None:
    """Assert a fresh instance reports the closed unselected markers."""
    fresh = UniversalProwlerContract()
    info = fresh.safe_request_info(None)
    assert info["filters"] == "unselected"
    assert info["selected_provider"] == "unselected"


def test_provider_key_rejection_clears_selection_before_early_return(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the provider-key early return clears all three held values first."""
    contract = _contract()
    parsed = contract.parse_input(
        {
            **provider_forms["aws"],
            "prowler_provider": ["aws"],
            "prowler_service": ["aws/s3"],
        }
    )
    assert contract.safe_request_info(parsed)["filters"] == "service=aws/s3"
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input({**provider_forms["aws"], "provider": "aws"})
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )
    assert contract.safe_request_info(None)["filters"] == "unselected"
    assert contract.safe_request_info(None)["selected_provider"] == "unselected"
    assert contract.safe_request_info(parsed)["filters"] == "unselected"
    assert contract.safe_request_info(parsed)["selected_provider"] == "unselected"


def test_each_worker_thread_executes_its_own_selection(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert two worker threads sharing one instance never cross selections."""
    forms = provider_forms
    factory = _RecordingFactory()
    contract = UniversalProwlerContract(factory)
    barrier = threading.Barrier(2)

    def _injection(provider: str, scope: dict[str, list[str]]) -> None:
        parsed = contract.parse_input(
            {**forms[provider], "prowler_provider": [provider], **scope}
        )
        barrier.wait(timeout=5)
        contract.execute(ProwlerConfig(), parsed)

    first = threading.Thread(
        target=_injection,
        args=("aws", {"prowler_service": ["aws/s3"]}),
        name="worker-aws-s3",
    )
    second = threading.Thread(
        target=_injection,
        args=("azure", {"prowler_compliance": ["cis/azure"]}),
        name="worker-azure-cis",
    )
    first.start()
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()
    assert len(factory.calls) == 2
    by_ident = {
        ident: (name, service, compliance)
        for ident, name, service, compliance in factory.calls
    }
    assert len(by_ident) == 2
    assert set(by_ident.values()) == {
        ("aws", "s3", None),
        ("azure", None, "cis_3.0_azure"),
    }


def test_failed_parse_in_one_thread_keeps_another_thread_run_intact(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a failed parse on one worker cannot corrupt another worker's run."""
    forms = provider_forms["aws"]
    factory = _RecordingFactory()
    contract = UniversalProwlerContract(factory)
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def _healthy_run() -> None:
        outcomes["healthy_ident"] = threading.get_ident()
        parsed = contract.parse_input(
            {
                **forms,
                "prowler_provider": ["aws"],
                "prowler_service": ["aws/s3"],
            }
        )
        barrier.wait(timeout=5)
        try:
            outcomes["healthy"] = contract.execute(ProwlerConfig(), parsed)
        except ValueError as error:
            outcomes["healthy"] = error

    def _broken_run() -> None:
        try:
            contract.parse_input(
                {
                    **forms,
                    "prowler_provider": ["aws"],
                    "prowler_service": ["scope-canary-bad"],
                }
            )
        except ContractInputError:
            pass
        barrier.wait(timeout=5)
        provider = AzureProviderInput(
            provider="azure",
            azure_tenant_id="tenant-id",
            azure_client_id="client-id",
            azure_client_secret=SecretStr("client-secret"),
            azure_subscription_id="subscription-id",
            azure_provider="AzureCloud",
        )
        try:
            outcomes["broken"] = contract.execute(ProwlerConfig(), provider)
        except ValueError as error:
            outcomes["broken"] = error

    first = threading.Thread(target=_healthy_run, name="worker-healthy")
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
    ident, name, service, compliance = factory.calls[0]
    assert ident == outcomes["healthy_ident"]
    assert name == "aws"
    assert service == "s3"
    assert compliance is None
