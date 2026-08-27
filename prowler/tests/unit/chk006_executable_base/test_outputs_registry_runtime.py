"""Executable expectations for CHK.006 shared infrastructure."""

import json
from typing import Any, ClassVar
from unittest.mock import Mock
from uuid import UUID

import pytest
from pyoaev.contracts.contract_config import ContractOutputType

from prowler.contracts import BaseProwlerContract, ContractExecutionOutcome
from prowler.models.configs.config_loader import ConfigLoader
from prowler.models.findings import OpenAevFinding


def _subject() -> Any:
    import prowler.contracts as contracts

    return contracts


def _concrete_contract_class(route: str = "aws", provider: str = "aws") -> type[Any]:
    subject = _subject()
    return type(
        "TestConcreteContract",
        (BaseProwlerContract,),
        {
            "contract_id": str(subject.stable_contract_id(route)),
            "external_id": f"prowler:{route}",
            "route_name": route,
            "provider": provider,
            "family": "base",
            "label": "Prowler test",
        },
    )


def test_dependency_stack_and_vulnerability_wire_value_are_current() -> None:
    """The installed SDK stack exposes the required vulnerability wire enum."""
    from importlib.metadata import version

    assert tuple(map(int, version("pydantic").split("."))) >= (2, 13, 3)
    assert tuple(map(int, version("pydantic-settings").split("."))) >= (2, 14, 0)
    assert ContractOutputType.Vulnerability.value == "vulnerability"


def test_registered_outputs_and_payload_preserve_and_project(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """All findings remain JSON text while FAILED alone becomes Vulnerability."""
    contract = _concrete_contract_class()()
    outputs = contract.build_contract().outputs
    assert [(item.type, item.field, item.isMultiple, item.isFindingCompatible) for item in outputs] == [
        (ContractOutputType.Text.value, "findings", True, False),
        (ContractOutputType.Vulnerability.value, "vulnerabilities", True, True),
    ]
    assert all(item.labels == ["prowler", "aws"] for item in outputs)

    payload = contract.output_payload(findings)
    assert tuple(payload) == ("findings", "vulnerabilities")
    assert len(payload["findings"]) == 3
    assert list(json.loads(payload["findings"][0])) == list(OpenAevFinding.model_fields)
    assert json.dumps(json.loads(payload["findings"][0]), separators=(",", ":")) == payload["findings"][0]
    assert payload["vulnerabilities"] == [
        {
            "name": "failed finding",
            "status": "VULNERABLE",
            "details": (
                "Description failed\nRemediation: Remediate failed "
                "(https://example.invalid/remediation)\nSeverity: HIGH (3)\n"
                "Cloud: provider=aws; account=account-placeholder; region=eu-west-1; "
                "resource=asset-failed [resource-failed]; compliance=cis, nis2"
            ),
        }
    ]
    assert "asset_id" not in payload["vulnerabilities"][0]


def test_trace_is_deterministic_flattened_and_secret_safe(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Trace reports flattened context and exact counts without sensitive values."""
    contract = _concrete_contract_class()()
    first = contract.execution_trace(findings)
    assert first == contract.execution_trace(findings)
    assert "Route: aws" in first
    assert "SUCCESS=1 FAILED=1 IGNORED=1" in first
    for field in OpenAevFinding.model_fields:
        assert f"{field}=" in first
    assert "credential" not in first.lower()
    assert "openaev-prowler-credential-" not in first


def test_route_uuid_strategy_is_stable_unique_and_version_five() -> None:
    """The committed namespace deterministically owns all canonical route IDs."""
    subject = _subject()
    first = tuple(subject.stable_contract_id(route.route_name) for route in subject.ROUTE_CATALOG)
    second = tuple(subject.stable_contract_id(route.route_name) for route in subject.ROUTE_CATALOG)
    assert first == second
    assert len(first) == len(set(first)) == 25
    assert all(isinstance(value, UUID) and value.version == 5 for value in first)


def test_registry_serializes_only_registered_concrete_contracts() -> None:
    """An explicit concrete class is resolvable and prepared for daemon config."""
    subject = _subject()
    contract_class = _concrete_contract_class()
    registry = subject.ProwlerContracts((contract_class,))
    identifier = str(subject.stable_contract_id("aws"))
    assert registry.resolve(identifier).__class__ is contract_class
    serialized = registry.contracts()
    assert len(serialized) == 1
    assert serialized[0]["contract_id"] == identifier
    assert json.loads(serialized[0]["contract_content"])["external_id"] == "prowler:aws"


def test_registry_rejects_abstract_duplicate_unstable_and_provider_mismatch() -> None:
    """Only one coherent concrete implementation can own a route and UUID."""
    subject = _subject()
    valid = _concrete_contract_class()
    with pytest.raises(ValueError):
        subject.ProwlerContracts((BaseProwlerContract,))
    with pytest.raises(ValueError):
        subject.ProwlerContracts((valid, valid))
    with pytest.raises(ValueError):
        subject.ProwlerContracts((_concrete_contract_class(provider="gcp"),))
    unstable = _concrete_contract_class()
    unstable.contract_id = "9d5b71f8-f36f-50ee-a896-d7ff41f541f9"
    with pytest.raises(ValueError):
        subject.ProwlerContracts((unstable,))


class _RuntimeContract(BaseProwlerContract):
    contract_id: ClassVar[str]
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Runtime test"
    events: ClassVar[list[str]] = []
    outcome: ClassVar[ContractExecutionOutcome]

    def parse_input(self, raw_input: Any) -> Any:
        self.events.append(f"parse:{tuple(raw_input)}")
        if "secret_marker" in raw_input:
            raise ValueError("unsafe exception contains SECRET-MARKER")
        return object()

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        self.events.append("execute")
        return self.outcome


def _message(identifier: str, *, fallback: str | None = None, content: dict[str, Any] | None = None) -> dict[str, Any]:
    injection: dict[str, Any] = {
        "inject_id": "inject-test",
        "injector_contract_id": identifier,
        "inject_content": content or {"aws_region": "eu-west-1"},
    }
    if fallback is not None:
        injection["convertedContent"] = {"contract_id": fallback, "ignored": "not-input"}
    return {"injection": injection, "ignored": {"secret_marker": "SECRET-MARKER"}}


def _runtime(findings: tuple[OpenAevFinding, ...]) -> tuple[Any, Mock]:
    from prowler._core.cli_engine import CommandResult, ExecutionSpecification, OutputSpecification
    from prowler.injector import ProwlerInjector

    subject = _subject()
    identifier = str(subject.stable_contract_id("aws"))
    _RuntimeContract.contract_id = identifier
    _RuntimeContract.events = []
    _RuntimeContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(
            specification=ExecutionSpecification(
                executable="/bin/true", arguments=(), environment=(), working_directory=None,
                input_bytes=b"", output=OutputSpecification(), timeout_seconds=1,
                maximum_accepted_output_bytes=1,
            ),
            return_code=0,
        ),
        findings=findings,
    )
    helper = Mock()
    helper.api.inject.execution_reception.side_effect = lambda **_: _RuntimeContract.events.append("reception")
    injector = ProwlerInjector(ConfigLoader(), helper, registry=subject.ProwlerContracts((_RuntimeContract,)))
    return injector, helper


@pytest.mark.parametrize("primary", (True, False))
def test_runtime_accepts_both_id_shapes_and_calls_success_once(
    findings: tuple[OpenAevFinding, ...], primary: bool
) -> None:
    """Reception precedes one parse/execute and one separated success callback."""
    subject = _subject()
    identifier = str(subject.stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    message = _message(identifier) if primary else _message("", fallback=identifier)
    if not primary:
        del message["injection"]["injector_contract_id"]
    injector.process_message(message)
    assert _RuntimeContract.events == ["reception", "parse:('aws_region',)", "execute"]
    helper.api.inject.execution_callback.assert_called_once()
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "SUCCESS"
    assert callback["execution_action"] == "complete"
    assert isinstance(callback["execution_duration"], int)
    assert json.loads(callback["execution_output_structured"])["findings"]
    assert callback["execution_message"].startswith("Route: aws")


@pytest.mark.parametrize("unknown", (False, True))
def test_runtime_conflict_or_unknown_is_one_safe_error_without_execution(
    findings: tuple[OpenAevFinding, ...], unknown: bool
) -> None:
    """Ambiguous/unregistered identity cannot execute or leak raw content."""
    subject = _subject()
    identifier = str(subject.stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    selected = str(subject.stable_contract_id("gcp")) if unknown else identifier
    fallback = None if unknown else str(subject.stable_contract_id("gcp"))
    injector.process_message(_message(selected, fallback=fallback, content={"secret_marker": "SECRET-MARKER"}))
    assert _RuntimeContract.events == ["reception"]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert "execution_output_structured" not in callback
    assert "SECRET-MARKER" not in callback["execution_message"]
    helper.api.inject.execution_callback.assert_called_once()


def test_default_registry_and_daemon_config_remain_empty() -> None:
    """CHK.006 defaults to no executable contract until CHK.007 registers one."""
    subject = _subject()
    assert subject.DEFAULT_PROWLER_CONTRACTS.contracts() == []
    daemon = ConfigLoader().to_daemon_config()
    assert daemon.config_hints["injector_contracts"]["data"] == []
