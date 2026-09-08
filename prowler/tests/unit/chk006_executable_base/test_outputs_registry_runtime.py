"""Executable expectations for CHK.006 shared infrastructure."""

import json
import logging
from dataclasses import replace
from typing import Any, ClassVar, cast
from unittest.mock import Mock, call
from uuid import UUID

import pytest
from pyoaev.configuration import ConfigLoaderOAEV  # type: ignore[import-untyped]
from pyoaev.contracts.contract_config import (  # type: ignore[import-untyped]
    ContractOutputType,
)
from pyoaev.utils import AppLogger  # type: ignore[import-untyped]

from prowler._core.cli_engine import (
    CliEngineError,
    ExecutionError,
    ParsingError,
    PolicyError,
    ResolutionError,
)
from prowler.contracts import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
)
from prowler.models.configs.config_loader import (
    ConfigLoader,
    InjectorConfig,
    ProwlerConfig,
)
from prowler.models.findings import (
    OcsfPreviewRecord,
    OpenAevFinding,
    map_ocsf_finding,
)


def _config() -> ConfigLoader:
    return cast(
        ConfigLoader,
        ConfigLoader.model_construct(
            openaev=ConfigLoaderOAEV(
                url="http://127.0.0.1:8080", token="runtime-test-token"
            ),
            injector=InjectorConfig(id="injector-test"),
            prowler=ProwlerConfig(),
        ),
    )


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
    assert [
        (item.type, item.field, item.isMultiple, item.isFindingCompatible)
        for item in outputs
    ] == [
        (ContractOutputType.Text.value, "findings", True, False),
        (ContractOutputType.Vulnerability.value, "vulnerabilities", True, True),
    ]
    assert all(item.labels == ["prowler", "aws"] for item in outputs)

    payload = contract.output_payload(findings)
    assert tuple(payload) == ("findings", "vulnerabilities")
    assert len(payload["findings"]) == 3
    assert list(json.loads(payload["findings"][0])) == list(OpenAevFinding.model_fields)
    assert (
        json.dumps(json.loads(payload["findings"][0]), separators=(",", ":"))
        == payload["findings"][0]
    )
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


def test_contract_forwards_dynamic_trace_config_and_safe_request_info(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Subclass columns and allowlisted model context reach the renderer."""
    contract_class = _concrete_contract_class()
    contract_class.output_trace_config = staticmethod(
        lambda: {"columns": [{"title": "Description", "path": "description"}]}
    )
    contract = contract_class()
    provider = contract.parse_input(
        {
            "aws_access_key_id": "CANARY-ACCESS-KEY",
            "aws_secret_access_key": "CANARY-SECRET",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
            "aws_session_token": "CANARY-SESSION",
        }
    )
    first = contract.render_trace(provider, findings, 4)
    assert first == contract.render_trace(provider, findings, 4)
    assert "Description" in first
    assert "Description failed" in first
    assert "account" in first and "123456789012" in first
    assert "region" in first and "eu-west-1" in first
    assert all(
        marker not in first
        for marker in ("CANARY-ACCESS-KEY", "CANARY-SECRET", "CANARY-SESSION")
    )


def test_route_uuid_strategy_is_stable_unique_and_version_five() -> None:
    """The committed namespace deterministically owns all canonical route IDs."""
    subject = _subject()
    first = tuple(
        subject.stable_contract_id(route.route_name) for route in subject.ROUTE_CATALOG
    )
    second = tuple(
        subject.stable_contract_id(route.route_name) for route in subject.ROUTE_CATALOG
    )
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
    parse_failure: ClassVar[Exception | None] = None
    render_failure: ClassVar[bool] = False
    use_base_renderer: ClassVar[bool] = False

    def parse_input(self, raw_input: Any) -> Any:
        self.events.append(f"parse:{tuple(raw_input)}")
        if self.parse_failure is not None:
            raise self.parse_failure
        return super().parse_input(raw_input)

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        self.events.append("execute")
        return self.outcome

    def render_trace(
        self, provider: Any, findings: Any, duration: int, **kwargs: Any
    ) -> str:
        self.events.append(
            "render:error" if kwargs.get("is_error") else "render:success"
        )
        if self.render_failure:
            raise RuntimeError("RENDERER-EXCEPTION-CANARY")
        if self.use_base_renderer:
            return super().render_trace(provider, findings, duration, **kwargs)
        if kwargs.get("is_error"):
            return f"CONTRACT RICH ERROR\n{kwargs['error_message']}"
        return "CONTRACT RICH SUCCESS"


def _message(
    identifier: str,
    *,
    fallback: str | None = None,
    content: dict[str, Any] | None = None,
) -> dict[str, Any]:
    injection: dict[str, Any] = {
        "inject_id": "inject-test",
        "injector_contract_id": identifier,
        "inject_content": content
        or {
            "aws_access_key_id": "runtime-access",
            "aws_secret_access_key": "runtime-secret",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
        },
    }
    if fallback is not None:
        injection["convertedContent"] = {
            "contract_id": fallback,
            "ignored": "not-input",
        }
    return {"injection": injection, "ignored": {"secret_marker": "SECRET-MARKER"}}


def _runtime(findings: tuple[OpenAevFinding, ...]) -> tuple[Any, Mock]:
    from prowler._core.cli_engine import (
        CommandResult,
        ExecutionSpecification,
        OutputSpecification,
    )
    from prowler.injector import ProwlerInjector

    subject = _subject()
    identifier = str(subject.stable_contract_id("aws"))
    _RuntimeContract.contract_id = identifier
    _RuntimeContract.events = []
    _RuntimeContract.parse_failure = None
    _RuntimeContract.render_failure = False
    _RuntimeContract.use_base_renderer = False
    _RuntimeContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(
            specification=ExecutionSpecification(
                executable="/opt/prowler/bin/prowler",
                arguments=("--ARG-CANARY", "FORM-VALUE-CANARY"),
                environment=(("ENV-CANARY", "ACCESS-KEY-CANARY"),),
                working_directory="/TEMP-CREDENTIAL-PATH-CANARY",
                input_bytes=b"STDIN-CANARY",
                output=OutputSpecification(),
                timeout_seconds=1,
                maximum_accepted_output_bytes=1,
            ),
            return_code=0,
        ),
        findings=findings,
        raw_record_count=3,
        raw_output_bytes=4096,
    )
    helper = Mock()
    helper.api.inject.execution_reception.side_effect = (
        lambda **_: _RuntimeContract.events.append("reception")
    )
    injector = ProwlerInjector(
        _config(), helper, registry=subject.ProwlerContracts((_RuntimeContract,))
    )
    return injector, helper


def _lightweight_mapped_findings(
    count: int, *, description_length: int = 1, description_character: str = "d"
) -> tuple[OpenAevFinding, ...]:
    """Map a full synthetic OCSF record set through the production mapper."""
    return tuple(
        map_ocsf_finding(
            {
                "finding_info": {
                    "uid": f"check-{index}",
                    "title": f"Check {index}",
                    "desc": description_character * description_length,
                },
                "status": "New",
                "status_code": "PASS",
                "severity": "Low",
                "resources": [{"uid": f"r-{index}", "name": f"R {index}"}],
                "cloud": {
                    "provider": "aws",
                    "region": "eu-west-1",
                    "account": {"uid": "account"},
                },
                "remediation": {"desc": "fix", "references": []},
            },
            record_index=index,
        )
        for index in range(count)
    )


_LISTENER_START = "[PROWLER_INJECTOR] - Listener starting"
_INVALID_MESSAGE = "[PROWLER_INJECTOR] - Invalid injection message rejected"
_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"

_GUIDANCE = {
    "cli_engine_error": "Review the injector configuration and retry the assessment.",
    "policy_rejected": (
        "Correct the assessment request to satisfy the execution policy."
    ),
    "policy_evaluation_failed": "Review the injector policy configuration and retry.",
    "resolution_failed": (
        "Check that prowler.executable_path points to an available executable."
    ),
    "execution_failed": (
        "Verify the Prowler runtime is available and retry the assessment."
    ),
    "timeout": (
        "Reduce the assessment scope or investigate Prowler runtime performance "
        "before retrying."
    ),
    "process_start_failed": (
        "Verify the Prowler process can start with the configured executable."
    ),
    "unsuccessful_process": (
        "Review the Prowler configuration and retry the assessment."
    ),
    "output_too_large_after_capture": (
        "Reduce the assessment scope so captured output stays within the injector "
        "limit."
    ),
    "parsing_failed": "Verify Prowler emits valid JSON-OCSF output and retry.",
    "invalid_input": "Correct the listed assessment fields and retry.",
    "rendering_failed": "Review injector trace rendering configuration and retry.",
    "callback_failed": "Check OpenAEV connectivity and retry callback delivery.",
    "unexpected_failure": "Review injector configuration and retry the assessment.",
}


def _assert_logger_excludes(helper: Mock, *markers: str) -> None:
    rendered_calls = repr(helper.injector_logger.method_calls) + repr(
        helper.injector_logger.local_logger.method_calls
    )
    assert all(marker not in rendered_calls for marker in markers)


def test_runtime_start_logs_one_fixed_listener_event() -> None:
    """Listener startup exposes bounded injector and executable facts."""
    from prowler.injector import ProwlerInjector

    config = _config()
    helper = Mock()
    registry = _subject().DEFAULT_PROWLER_CONTRACTS
    injector = ProwlerInjector(config, helper, registry=registry)

    injector.start()

    helper.listen.assert_called_once_with(message_callback=injector.process_message)
    message, metadata = helper.injector_logger.info.call_args.args
    assert message == _LISTENER_START
    assert metadata["injector_id"] == "injector-test"
    assert metadata["injector_name"] == "Prowler"
    assert metadata["registered_contract_count"] == 25
    assert metadata["configured_executable_path"] == "/usr/local/bin/prowler"
    assert set(metadata) == {
        "injector_id",
        "injector_name",
        "registered_contract_count",
        "configured_executable_path",
        "executable_is_absolute",
        "executable_exists",
        "executable_is_file",
        "executable_is_executable",
    }


@pytest.mark.parametrize(
    "message",
    (
        {},
        {"injection": "RAW-INJECTION-CANARY"},
        {"injection": {"inject_id": "", "inject_content": "FORM-VALUE-CANARY"}},
    ),
)
def test_runtime_rejects_invalid_envelope_with_fixed_value_free_warning(
    findings: tuple[OpenAevFinding, ...], message: dict[str, Any]
) -> None:
    """An unusable envelope or inject ID is warned about without payload data."""
    injector, helper = _runtime(findings)

    injector.process_message(message)

    expected_reason = (
        "missing_injection"
        if "injection" not in message
        else (
            "invalid_injection"
            if not isinstance(message["injection"], dict)
            else "missing_inject_id"
        )
    )
    helper.injector_logger.warning.assert_called_once_with(
        _INVALID_MESSAGE, {"reason_code": expected_reason}
    )
    helper.injector_logger.error.assert_not_called()
    helper.api.inject.execution_reception.assert_not_called()
    helper.api.inject.execution_callback.assert_not_called()
    _assert_logger_excludes(
        helper, "RAW-INJECTION-CANARY", "FORM-VALUE-CANARY", "inject_content"
    )


def test_runtime_logs_fixed_safe_success_lifecycle(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A successful assessment logs every fixed correlated lifecycle stage."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)

    injector.process_message(_message(identifier))

    calls = helper.injector_logger.method_calls
    assert [item.args[0] for item in calls] == [
        _ASSESSMENT_RECEIVED,
        _RECEPTION_ACKNOWLEDGED,
        _CONTRACT_RESOLVED,
        _ASSESSMENT_VALIDATED,
        _EXECUTION_STARTED,
        _ASSESSMENT_SUCCEEDED,
        _CALLBACK_COMPLETED,
    ]
    assert all(item.args[1]["inject_id"] == "inject-test" for item in calls)
    assert all(0 <= item.args[1]["elapsed_ms"] <= 86_400_000 for item in calls)
    success_meta = calls[-2].args[1]
    assert success_meta["contract_id"] == identifier
    assert success_meta["route"] == "aws"
    assert success_meta["provider"] == "aws"
    assert success_meta["status"] == "SUCCESS"
    assert success_meta["finding_count"] == 3
    assert success_meta["vulnerability_count"] == 1
    assert success_meta["raw_record_count"] == 3
    assert success_meta["raw_output_bytes"] == 4096
    assert success_meta["artifact_capture_phase"] == "complete"
    assert success_meta["ocsf_mapping_phase"] == "complete"
    assert success_meta["aws_account_id"] == "123456789012"
    assert success_meta["aws_region"] == "eu-west-1"
    callback_meta = calls[-1].args[1]
    assert callback_meta["assessment_status"] == "SUCCESS"
    assert callback_meta["delivery_status"] == "SUCCESS"
    assert "status" not in callback_meta
    assert "attempted_status" not in callback_meta
    assert calls[-1] == call.debug(_CALLBACK_COMPLETED, callback_meta)
    _assert_logger_excludes(
        helper,
        "runtime-access",
        "runtime-secret",
        "ARG-CANARY",
        "ENV-CANARY",
        "STDIN-CANARY",
        "TEMP-CREDENTIAL-PATH-CANARY",
        "CONTRACT RICH SUCCESS",
        "success finding",
        "failed finding",
        "ignored finding",
    )


def test_runtime_keeps_all_2410_mapped_findings_and_bounds_trace() -> None:
    """An under-budget callback keeps the complete mapped record set."""
    identifier = str(_subject().stable_contract_id("aws"))
    mapped_findings = _lightweight_mapped_findings(2410)
    injector, helper = _runtime(mapped_findings)
    _RuntimeContract.use_base_renderer = True
    _RuntimeContract.outcome = replace(
        _RuntimeContract.outcome,
        raw_record_count=2410,
        raw_output_bytes=987_654,
        raw_preview=tuple(
            OcsfPreviewRecord(
                finding_title=f"safe-check-{index}",
                finding_uid=f"safe-uid-{index}",
                status="New",
                status_code="PASS",
                severity="High",
                resource_name=f"safe-resource-{index}",
                resource_uid=f"safe-resource-uid-{index}",
                cloud_provider="aws",
                cloud_region="eu-west-1",
                cloud_account="safe-account",
            )
            for index in range(20)
        ),
    )
    assert len(_RuntimeContract.outcome.raw_preview) == 10

    injector.process_message(_message(identifier))

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    trace = callback["execution_message"]
    structured = json.loads(callback["execution_output_structured"])
    assert callback["execution_status"] == "SUCCESS"
    assert tuple(structured) == ("findings", "vulnerabilities")
    assert len(structured["findings"]) == 2410
    assert structured["vulnerabilities"] == []
    assert json.loads(structured["findings"][0])["value"] == "Check 0"
    assert json.loads(structured["findings"][-1])["value"] == "Check 2409"
    assert "raw_preview" not in structured
    assert "raw_records" not in structured
    assert "Total raw records: 2410" in trace
    assert "Records omitted: 2400" in trace
    assert "safe-check-9" in trace
    assert "safe-check-10" not in trace
    assert len(trace) < 25_000


def test_runtime_rejects_oversized_maximal_structured_output_without_partial_data() -> (
    None
):
    """A maximal mapped set beyond 32 MiB closes with exact byte evidence."""
    identifier = str(_subject().stable_contract_id("aws"))
    mapped_findings = _lightweight_mapped_findings(
        2410, description_length=4_700, description_character="€"
    )
    injector, helper = _runtime(mapped_findings)
    _RuntimeContract.use_base_renderer = True
    _RuntimeContract.outcome = replace(
        _RuntimeContract.outcome,
        raw_record_count=2410,
        raw_output_bytes=104_857_600,
    )

    injector.process_message(_message(identifier))

    helper.api.inject.execution_callback.assert_called_once()
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert callback["execution_action"] == "complete"
    assert "execution_output_structured" not in callback
    assert _RuntimeContract.events.count("render:success") == 0
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["failure_kind"] == "structured_output_too_large"
    assert error_meta["maximum_accepted_structured_output_bytes"] == 32 * 1024 * 1024
    assert (
        error_meta["structured_output_bytes"]
        > error_meta["maximum_accepted_structured_output_bytes"]
    )
    assert (
        f"Structured output bytes: {error_meta['structured_output_bytes']}"
        in callback["execution_message"]
    )
    assert (
        "Accepted structured output byte limit: 33554432"
        in callback["execution_message"]
    )


def test_runtime_logs_bounded_value_free_contract_input_issues(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Emit one bounded value-free input ERROR through the safe logger boundary."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ContractInputError(
        (
            ContractInputIssue(("aws_secret_access_key",), "string_too_short"),
            ContractInputIssue(("unexpected",), "extra_forbidden"),
        )
    )

    injector.process_message(_message(identifier))

    helper.injector_logger.error.assert_not_called()
    helper.injector_logger.local_logger.error.assert_called_once()
    error_message = helper.injector_logger.local_logger.error.call_args.args[0]
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_message == _ASSESSMENT_FAILED
    assert error_meta["inject_id"] == "inject-test"
    assert error_meta["contract_id"] == identifier
    assert error_meta["route"] == "aws"
    assert error_meta["provider"] == "aws"
    assert error_meta["status"] == "ERROR"
    assert error_meta["stage"] == "input_validation"
    assert error_meta["failure_kind"] == "invalid_input"
    assert error_meta["failure_summary"] == "The assessment input was invalid."
    assert error_meta["operator_guidance"] == _GUIDANCE["invalid_input"]
    assert error_meta["issues"] == [
        {
            "location": ["aws_secret_access_key"],
            "type": "string_too_short",
        },
        {"location": ["unrecognized_field"], "type": "extra_forbidden"},
    ]
    assert error_meta["issues_truncated"] is True
    assert 0 <= error_meta["elapsed_ms"] <= 86_400_000
    assert (
        helper.injector_logger.local_logger.error.call_args.kwargs["exc_info"] is False
    )
    callback_meta = helper.injector_logger.method_calls[-1].args[1]
    assert callback_meta["assessment_status"] == "ERROR"
    assert callback_meta["delivery_status"] == "SUCCESS"
    assert "status" not in callback_meta
    assert "attempted_status" not in callback_meta
    assert callback_meta["inject_id"] == "inject-test"
    _assert_logger_excludes(
        helper,
        "FORM-VALUE-CANARY",
        "runtime-access",
        "runtime-secret",
        "Invalid Prowler contract input",
        "SECRET-MARKER",
    )


def test_runtime_guides_a_real_invalid_aws_account_without_echoing_it(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A real contract pattern failure receives its exact bounded guidance."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    invalid_account = "１２３４５６７８９０１２-ACCOUNT-CANARY"

    injector.process_message(
        _message(
            identifier,
            content={
                "aws_access_key_id": "runtime-access",
                "aws_secret_access_key": "runtime-secret",
                "aws_account_id": invalid_account,
                "aws_region": "eu-west-1",
            },
        )
    )

    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    expected = "AWS account ID must contain exactly 12 ASCII digits."
    assert error_meta["failure_kind"] == "invalid_input"
    assert error_meta["operator_guidance"] == expected
    assert error_meta["issues"] == [
        {
            "location": ["aws", "aws_account_id"],
            "type": "string_pattern_mismatch",
        }
    ]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert "Error code: invalid_input" in callback["execution_message"]
    assert callback["execution_message"].count(expected) == 1
    assert invalid_account not in callback["execution_message"]
    _assert_logger_excludes(helper, invalid_account)


def test_runtime_guides_a_real_known_field_with_allowlisted_words(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Known field and issue allowlists form one bounded correction sentence."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    invalid_region = {"REGION-CANARY": "FORM-VALUE-CANARY"}

    injector.process_message(
        _message(
            identifier,
            content={
                "aws_access_key_id": "runtime-access",
                "aws_secret_access_key": "runtime-secret",
                "aws_account_id": "123456789012",
                "aws_region": invalid_region,
            },
        )
    )

    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    expected = "AWS region must be text."
    assert error_meta["operator_guidance"] == expected
    assert len(expected) <= 100
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_message"].count(expected) == 1
    assert "REGION-CANARY" not in callback["execution_message"]
    _assert_logger_excludes(helper, "REGION-CANARY", "FORM-VALUE-CANARY")


@pytest.mark.parametrize(
    "issues",
    (
        (ContractInputIssue(("aws", "aws_account_id"), "string_pattern_mismatch"),),
        (ContractInputIssue(("unknown-canary",), "missing"),),
        (
            ContractInputIssue(
                ("aws", "aws_account_id", "aws", "aws_account_id"),
                "string_pattern_mismatch",
            ),
        ),
    ),
)
def test_runtime_gives_forged_or_untrusted_issues_only_generic_guidance(
    findings: tuple[OpenAevFinding, ...],
    issues: tuple[ContractInputIssue, ...],
) -> None:
    """Untrusted issue structures cannot select field-specific guidance."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ContractInputError(issues)

    injector.process_message(_message(identifier))

    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["operator_guidance"] == _GUIDANCE["invalid_input"]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_message"].count(_GUIDANCE["invalid_input"]) == 1
    assert "AWS account ID must contain" not in callback["execution_message"]


def test_runtime_resolution_guidance_ignores_all_process_canaries(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Resolution guidance is fixed independently of command and error internals."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    command_result = replace(
        _RuntimeContract.outcome.command_result,
        stdout=b"STDOUT-RESOLUTION-CANARY",
        stderr=b"STDERR-RESOLUTION-CANARY",
        error=ResolutionError("MESSAGE-RESOLUTION-CANARY"),
    )
    _RuntimeContract.outcome = ContractExecutionOutcome(
        command_result=command_result,
        error=command_result.error,
    )

    injector.process_message(_message(identifier))

    expected = _GUIDANCE["resolution_failed"]
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert error_meta["operator_guidance"] == expected
    assert callback["execution_message"].count(expected) == 1
    for canary in (
        "MESSAGE-RESOLUTION-CANARY",
        "TEMP-CREDENTIAL-PATH-CANARY",
        "ARG-CANARY",
        "ENV-CANARY",
        "STDIN-CANARY",
        "STDOUT-RESOLUTION-CANARY",
        "STDERR-RESOLUTION-CANARY",
    ):
        assert canary not in callback["execution_message"]
        _assert_logger_excludes(helper, canary)


def test_real_error_renderer_receives_no_form_values_or_findings(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """The actual Rich error trace receives no parsed form or finding content."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.use_base_renderer = True
    _RuntimeContract.outcome = ContractExecutionOutcome(
        command_result=_RuntimeContract.outcome.command_result,
        findings=findings,
        error=ResolutionError("ERROR-MESSAGE-CANARY"),
    )

    injector.process_message(_message(identifier))

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    trace = callback["execution_message"]
    assert "Error code: resolution_failed" in trace
    assert _GUIDANCE["resolution_failed"] in trace
    for canary in (
        "runtime-access",
        "runtime-secret",
        "123456789012",
        "eu-west-1",
        "success finding",
        "failed finding",
        "ignored finding",
        "ERROR-MESSAGE-CANARY",
    ):
        assert canary not in trace


@pytest.mark.parametrize(
    ("error", "return_code", "expected_kind", "expected_return_code"),
    (
        (CliEngineError("EXCEPTION-STRING-CANARY"), 0, "cli_engine_error", None),
        (PolicyError("EXCEPTION-STRING-CANARY"), 0, "policy_rejected", None),
        (
            PolicyError("EXCEPTION-STRING-CANARY", kind="policy_evaluation_failed"),
            0,
            "policy_evaluation_failed",
            None,
        ),
        (
            ResolutionError("EXCEPTION-STRING-CANARY"),
            0,
            "resolution_failed",
            None,
        ),
        (
            ExecutionError(
                "EXCEPTION-STRING-CANARY",
                stdout=b"STDOUT-BYTES-CANARY",
                stderr=b"STDERR-BYTES-CANARY",
                return_code=23,
                cause="EXCEPTION-CAUSE-CANARY",
            ),
            23,
            "execution_failed",
            23,
        ),
        (
            ExecutionError("EXCEPTION-STRING-CANARY", kind="timeout"),
            0,
            "timeout",
            None,
        ),
        (
            ExecutionError("EXCEPTION-STRING-CANARY", kind="process_start_failed"),
            0,
            "process_start_failed",
            None,
        ),
        (
            ExecutionError(
                "EXCEPTION-STRING-CANARY",
                kind="unsuccessful_process",
                return_code=31,
            ),
            31,
            "unsuccessful_process",
            31,
        ),
        (
            ExecutionError(
                "EXCEPTION-STRING-CANARY",
                kind="output_too_large_after_capture",
            ),
            0,
            "output_too_large_after_capture",
            None,
        ),
        (
            ParsingError(
                "EXCEPTION-STRING-CANARY",
                stdout=b"STDOUT-BYTES-CANARY",
                stderr=b"STDERR-BYTES-CANARY",
                context=(("temporary_path", "/TEMP-CREDENTIAL-PATH-CANARY"),),
                cause="EXCEPTION-CAUSE-CANARY",
            ),
            0,
            "parsing_failed",
            None,
        ),
        (
            CliEngineError("EXCEPTION-STRING-CANARY", kind="ATTACKER-KIND-CANARY"),
            0,
            "unexpected_failure",
            None,
        ),
        (RuntimeError("EXCEPTION-STRING-CANARY"), 19, "unexpected_failure", None),
    ),
)
def test_runtime_logs_only_allowlisted_assessment_failure_metadata(
    findings: tuple[OpenAevFinding, ...],
    error: Any,
    return_code: int,
    expected_kind: str,
    expected_return_code: int | None,
) -> None:
    """Assessment results expose a closed failure kind and optional return code."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    command_result = replace(
        _RuntimeContract.outcome.command_result, return_code=return_code
    )
    _RuntimeContract.outcome = ContractExecutionOutcome(
        command_result=command_result,
        findings=findings,
        error=error,
    )

    injector.process_message(_message(identifier))

    helper.injector_logger.error.assert_not_called()
    helper.injector_logger.local_logger.error.assert_called_once()
    error_message = helper.injector_logger.local_logger.error.call_args.args[0]
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_message == _ASSESSMENT_FAILED
    assert error_meta["inject_id"] == "inject-test"
    assert error_meta["contract_id"] == identifier
    assert error_meta["route"] == "aws"
    assert error_meta["provider"] == "aws"
    assert error_meta["status"] == "ERROR"
    assert error_meta["stage"] == "assessment_execution"
    assert error_meta["failure_kind"] == expected_kind
    assert error_meta["failure_summary"]
    assert error_meta["operator_guidance"] == _GUIDANCE[expected_kind]
    assert 0 <= error_meta["elapsed_ms"] <= 86_400_000
    if expected_return_code is not None:
        assert error_meta["return_code"] == expected_return_code
    else:
        assert "return_code" not in error_meta
    assert len(error_meta["operator_guidance"]) <= 100
    assert (
        helper.injector_logger.local_logger.error.call_args.kwargs["exc_info"] is False
    )
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert f"Error code: {expected_kind}" in callback["execution_message"]
    assert _GUIDANCE[expected_kind] in callback["execution_message"]
    assert callback["execution_message"].count(_GUIDANCE[expected_kind]) == 1
    assert "execution_output_structured" not in callback
    _assert_logger_excludes(
        helper,
        "EXCEPTION-STRING-CANARY",
        "EXCEPTION-CAUSE-CANARY",
        "STDOUT-BYTES-CANARY",
        "STDERR-BYTES-CANARY",
        "ATTACKER-KIND-CANARY",
        "TEMP-CREDENTIAL-PATH-CANARY",
        "CONTRACT RICH ERROR",
        "failed finding",
    )


def test_runtime_collapses_unexpected_exception_without_exception_details(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """An unexpected raised exception is classified without its string or repr."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = RuntimeError(
        "EXCEPTION-STRING-CANARY /TEMP-CREDENTIAL-PATH-CANARY"
    )

    injector.process_message(_message(identifier))

    helper.injector_logger.error.assert_not_called()
    helper.injector_logger.local_logger.error.assert_called_once()
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["stage"] == "input_validation"
    assert error_meta["failure_kind"] == "unexpected_failure"
    assert error_meta["operator_guidance"] == _GUIDANCE["unexpected_failure"]
    assert "issues" not in error_meta
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert "Error code: unexpected_failure" in callback["execution_message"]
    assert _GUIDANCE["unexpected_failure"] in callback["execution_message"]
    _assert_logger_excludes(
        helper, "EXCEPTION-STRING-CANARY", "TEMP-CREDENTIAL-PATH-CANARY"
    )


def test_runtime_error_record_never_inherits_an_outer_active_exception(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """The real ERROR LogRecord has no traceback even inside an outer except."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ContractInputError(())
    records: list[logging.LogRecord] = []

    class RecordHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    local_logger = logging.getLogger("tests.prowler.safe-error-record")
    local_logger.handlers = [RecordHandler()]
    local_logger.propagate = False
    local_logger.setLevel(logging.ERROR)
    app_logger = AppLogger.__new__(AppLogger)
    app_logger.local_logger = local_logger
    helper.injector_logger = app_logger

    try:
        raise RuntimeError("OUTER-EXCEPTION-CANARY")
    except RuntimeError:
        injector.process_message(_message(identifier))

    assert len(records) == 1
    record = records[0]
    formatted = logging.Formatter("%(levelname)s %(message)s %(attributes)s").format(
        record
    )
    assert not record.exc_info
    assert "OUTER-EXCEPTION-CANARY" not in formatted
    assert "Traceback" not in formatted
    assert "NoneType: None" not in formatted


def test_runtime_caps_and_normalizes_attacker_controlled_input_issues(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Attacker keys and error types cannot leak or amplify ERROR metadata."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    attacker_key = "SECRET-KEY-CANARY\nFORGED-LOG-LINE"
    oversized_key = "OVERSIZED-KEY-CANARY" * 100
    _RuntimeContract.parse_failure = ContractInputError(
        tuple(
            ContractInputIssue(
                (attacker_key, oversized_key, f"ATTACKER-KEY-{index}", "too-deep"),
                f"ATTACKER-TYPE-{index}\nTYPE-CANARY",
            )
            for index in range(300)
        )
    )

    injector.process_message(_message(identifier))

    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["failure_kind"] == "invalid_input"
    assert error_meta["operator_guidance"] == _GUIDANCE["invalid_input"]
    assert 0 < len(error_meta["issues"]) <= 16
    assert error_meta["issues_omitted"] == 284
    assert error_meta["issues_truncated"] is True
    assert all(
        issue
        == {
            "location": [
                "unrecognized_field",
                "unrecognized_field",
                "unrecognized_field",
            ],
            "type": "invalid",
        }
        for issue in error_meta["issues"]
    )
    rendered = repr(error_meta)
    assert "SECRET-KEY-CANARY" not in rendered
    assert "FORGED-LOG-LINE" not in rendered
    assert "OVERSIZED-KEY-CANARY" not in rendered
    assert "ATTACKER-KEY" not in rendered
    assert "ATTACKER-TYPE" not in rendered
    assert "TYPE-CANARY" not in rendered
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert len(callback["execution_message"]) <= 2_000
    assert "Error code: invalid_input" in callback["execution_message"]
    assert callback["execution_message"].count(_GUIDANCE["invalid_input"]) == 1


@pytest.mark.parametrize("content", (None, "RAW-CONTENT-CANARY", ("tuple",)))
def test_runtime_classifies_missing_or_non_mapping_content_as_invalid_input(
    findings: tuple[OpenAevFinding, ...], content: object
) -> None:
    """Missing or non-mapping form content is invalid input with no issues."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    message = _message(identifier)
    message["injection"]["inject_content"] = content

    injector.process_message(message)

    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["stage"] == "input_validation"
    assert error_meta["failure_kind"] == "invalid_input"
    assert error_meta["operator_guidance"] == _GUIDANCE["invalid_input"]
    assert error_meta["issues"] == []
    _assert_logger_excludes(helper, "RAW-CONTENT-CANARY", "tuple")


def test_runtime_logger_failures_do_not_prevent_execution_or_callback(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Best-effort lifecycle logs cannot interrupt the assessment lifecycle."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    helper.injector_logger.info.side_effect = RuntimeError("LOGGER-INFO-CANARY")
    helper.injector_logger.debug.side_effect = RuntimeError("LOGGER-DEBUG-CANARY")

    injector.process_message(_message(identifier))

    assert "execute" in _RuntimeContract.events
    helper.api.inject.execution_callback.assert_called_once()
    assert (
        helper.api.inject.execution_callback.call_args.kwargs["data"][
            "execution_status"
        ]
        == "SUCCESS"
    )


def test_runtime_error_logger_failure_does_not_prevent_terminal_callback(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A failed safe ERROR logger is suppressed rather than retried unsafely."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ContractInputError(())
    helper.injector_logger.local_logger.error.side_effect = RuntimeError(
        "LOGGER-ERROR-CANARY"
    )

    injector.process_message(_message(identifier))

    helper.injector_logger.error.assert_not_called()
    helper.injector_logger.local_logger.error.assert_called_once()
    helper.api.inject.execution_callback.assert_called_once()


def test_runtime_renderer_failure_falls_back_without_a_second_render(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A broken success renderer yields one fixed safe terminal callback."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.render_failure = True

    injector.process_message(_message(identifier))

    assert _RuntimeContract.events.count("render:success") == 1
    assert "render:error" not in _RuntimeContract.events
    helper.api.inject.execution_callback.assert_called_once()
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    message = callback["execution_message"]
    assert "Error code: rendering_failed" in message
    assert "Reason: The OpenAEV execution trace could not be rendered." in message
    assert f"Action: {_GUIDANCE['rendering_failed']}" in message
    assert "Inject ID: inject-test" in message
    assert f"Contract: {identifier}" in message
    assert "Route: aws" in message and "Provider: aws" in message
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["stage"] == "output_preparation"
    assert error_meta["failure_kind"] == "rendering_failed"
    assert error_meta["operator_guidance"] == _GUIDANCE["rendering_failed"]
    assert len(error_meta["operator_guidance"]) <= 100
    _assert_logger_excludes(helper, "RENDERER-EXCEPTION-CANARY")


def test_runtime_error_renderer_failure_keeps_the_classified_code_and_guidance(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A broken error renderer falls back after its one permitted render attempt."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ContractInputError(())
    _RuntimeContract.render_failure = True

    injector.process_message(_message(identifier))

    assert _RuntimeContract.events.count("render:error") == 1
    assert "render:success" not in _RuntimeContract.events
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    message = callback["execution_message"]
    assert "Error code: invalid_input" in message
    assert "Reason: The assessment input was invalid." in message
    assert f"Action: {_GUIDANCE['invalid_input']}" in message
    assert "Inject ID: inject-test" in message
    assert f"Contract: {identifier}" in message
    error_meta = helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]
    assert error_meta["operator_guidance"] == _GUIDANCE["invalid_input"]
    _assert_logger_excludes(helper, "RENDERER-EXCEPTION-CANARY")


def test_runtime_callback_failure_is_contained_and_logged_once(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Callback delivery is attempted once and failure diagnostics stay fixed."""
    identifier = str(_subject().stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    helper.api.inject.execution_callback.side_effect = RuntimeError(
        "CALLBACK-EXCEPTION-CANARY RESPONSE-PAYLOAD-CANARY"
    )

    injector.process_message(_message(identifier))

    helper.api.inject.execution_callback.assert_called_once()
    callback_errors = [
        item
        for item in helper.injector_logger.local_logger.error.call_args_list
        if item.kwargs["extra"]["attributes"].get("stage") == "callback"
    ]
    assert len(callback_errors) == 1
    callback_meta = callback_errors[0].kwargs["extra"]["attributes"]
    assert callback_meta["failure_kind"] == "callback_failed"
    assert callback_meta["operator_guidance"] == _GUIDANCE["callback_failed"]
    assert len(callback_meta["operator_guidance"]) <= 100
    assert callback_errors[0].kwargs["exc_info"] is False
    _assert_logger_excludes(
        helper, "CALLBACK-EXCEPTION-CANARY", "RESPONSE-PAYLOAD-CANARY"
    )


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
    assert _RuntimeContract.events == [
        "reception",
        "parse:('aws_access_key_id', 'aws_secret_access_key', "
        "'aws_account_id', 'aws_region')",
        "execute",
        "render:success",
    ]
    helper.api.inject.execution_callback.assert_called_once()
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "SUCCESS"
    assert callback["execution_action"] == "complete"
    assert isinstance(callback["execution_duration"], int)
    assert json.loads(callback["execution_output_structured"])["findings"]
    assert callback["execution_message"] == "CONTRACT RICH SUCCESS"


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
    injector.process_message(_message(selected, fallback=fallback))
    assert _RuntimeContract.events == ["reception"]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert "execution_output_structured" not in callback
    assert "SECRET-MARKER" not in callback["execution_message"]
    helper.api.inject.execution_callback.assert_called_once()


def test_runtime_resolved_contract_uses_renderer_for_safe_error(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """A resolved parse failure is represented by the contract's safe renderer."""
    subject = _subject()
    identifier = str(subject.stable_contract_id("aws"))
    injector, helper = _runtime(findings)
    _RuntimeContract.parse_failure = ValueError(
        "unsafe exception contains SECRET-MARKER"
    )

    injector.process_message(_message(identifier))

    assert _RuntimeContract.events == [
        "reception",
        "parse:('aws_access_key_id', 'aws_secret_access_key', "
        "'aws_account_id', 'aws_region')",
        "render:error",
    ]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert "Error code: unexpected_failure" in callback["execution_message"]
    assert _GUIDANCE["unexpected_failure"] in callback["execution_message"]
    assert "SECRET-MARKER" not in callback["execution_message"]


def test_default_registry_and_daemon_config_register_executable_routes() -> None:
    """The daemon registers all executable routes through CHK.015."""
    subject = _subject()
    contracts = subject.DEFAULT_PROWLER_CONTRACTS.contracts()
    assert [item["contract_id"] for item in contracts] == [
        str(subject.stable_contract_id("aws")),
        str(subject.stable_contract_id("azure")),
        str(subject.stable_contract_id("gcp")),
        str(subject.stable_contract_id("kubernetes")),
        str(subject.stable_contract_id("aws/iam")),
        str(subject.stable_contract_id("aws/s3")),
        str(subject.stable_contract_id("aws/ec2")),
        str(subject.stable_contract_id("azure/iam")),
        str(subject.stable_contract_id("azure/storage")),
        str(subject.stable_contract_id("gcp/iam")),
        str(subject.stable_contract_id("gcp/compute")),
        str(subject.stable_contract_id("cis/aws")),
        str(subject.stable_contract_id("cis/azure")),
        str(subject.stable_contract_id("cis/gcp")),
        str(subject.stable_contract_id("cis/kubernetes")),
        str(subject.stable_contract_id("nis2/aws")),
        str(subject.stable_contract_id("nis2/azure")),
        str(subject.stable_contract_id("nis2/gcp")),
        str(subject.stable_contract_id("iso27001/aws")),
        str(subject.stable_contract_id("iso27001/azure")),
        str(subject.stable_contract_id("iso27001/gcp")),
        str(subject.stable_contract_id("iso27001/kubernetes")),
    ]
    daemon = _config().to_daemon_config()
    assert daemon.get("injector_contracts") == contracts
