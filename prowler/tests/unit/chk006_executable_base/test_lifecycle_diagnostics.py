"""Approved CHK.006 lifecycle diagnostics behavior."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, ClassVar, cast
from unittest.mock import Mock

import pytest
from pyoaev.configuration import ConfigLoaderOAEV  # type: ignore[import-untyped]

from prowler._core.cli_engine import (
    CliEngineError,
    CommandResult,
    ExecutionError,
    ExecutionSpecification,
    OutputSpecification,
    ParsingError,
    PolicyError,
)
from prowler.contracts import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
    ContractInputIssue,
    ProwlerContracts,
    stable_contract_id,
)
from prowler.injector import ProwlerInjector
from prowler.models.configs.config_loader import (
    ConfigLoader,
    InjectorConfig,
    ProwlerConfig,
)
from prowler.models.findings import OcsfMappingError, OpenAevFinding

_LISTENER_START = "[PROWLER_INJECTOR] - Listener starting"
_ASSESSMENT_RECEIVED = "[PROWLER_INJECTOR] - Assessment received"
_RECEPTION_ACKNOWLEDGED = "[PROWLER_INJECTOR] - Reception acknowledged"
_CONTRACT_RESOLVED = "[PROWLER_INJECTOR] - Contract resolved"
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment input validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution starting"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"
_CALLBACK_FAILED = "[PROWLER_INJECTOR] - Assessment callback failed"
_INVALID_MESSAGE = "[PROWLER_INJECTOR] - Invalid injection message rejected"

_CONTRACT_ID = str(stable_contract_id("aws"))
_RAW_CANARIES = (
    "RAW-ERROR-MESSAGE-CANARY",
    "RAW-CAUSE-CANARY",
    "STDOUT-CONTENT-CANARY",
    "STDERR-CONTENT-CANARY",
    "ACCESS-KEY-CANARY",
    "SECRET-CANARY",
    "SESSION-CANARY",
    "CLIENT-ID-CANARY",
    "TENANT-ID-CANARY",
    "GCP-JSON-CANARY",
    "KUBECONFIG-CANARY",
    "ARGUMENT-CANARY",
    "ENVIRONMENT-CANARY",
    "STDIN-CANARY",
    "FINDING-CANARY",
    "CALLBACK-PAYLOAD-CANARY",
)


def _specification(
    *,
    executable: str = "/opt/prowler/bin/prowler",
    parser: str = "json",
    timeout_seconds: float = 3600.0,
    maximum_bytes: int = 104_857_600,
) -> ExecutionSpecification:
    return ExecutionSpecification(
        executable=executable,
        arguments=("ARGUMENT-CANARY",),
        environment=(("ENVIRONMENT-CANARY", "SECRET-CANARY"),),
        working_directory=None,
        input_bytes=b"STDIN-CANARY",
        output=OutputSpecification(parser=parser),
        timeout_seconds=timeout_seconds,
        maximum_accepted_output_bytes=maximum_bytes,
    )


class _DiagnosticContract(BaseProwlerContract):
    contract_id = _CONTRACT_ID
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Diagnostic AWS"
    outcome: ClassVar[ContractExecutionOutcome]
    parse_failure: ClassVar[Exception | None] = None
    render_failure: ClassVar[bool] = False

    def parse_input(self, raw_input: Any) -> Any:
        if self.parse_failure is not None:
            raise self.parse_failure
        return super().parse_input(raw_input)

    def execute(self, config: Any, provider: Any) -> ContractExecutionOutcome:
        del config, provider
        return self.outcome

    def render_trace(
        self, provider: Any, findings: Any, duration: int, **kwargs: Any
    ) -> str:
        if self.render_failure:
            raise RuntimeError("RAW-ERROR-MESSAGE-CANARY")
        return super().render_trace(provider, findings, duration, **kwargs)


class _RealExecutionContract(BaseProwlerContract):
    """Exercise the real CLI and OCSF mapping boundary from the injector."""

    contract_id = _CONTRACT_ID
    external_id = "prowler:aws"
    route_name = "aws"
    provider = "aws"
    family = "base"
    label = "Real diagnostic AWS"


class _SerializationFailureContract(_DiagnosticContract):
    render_calls: ClassVar[int] = 0

    def output_payload(self, findings: Any) -> dict[str, list[Any]]:
        del findings
        raise RuntimeError("SERIALIZATION-FAILURE-CANARY")

    def render_trace(
        self, provider: Any, findings: Any, duration: int, **kwargs: Any
    ) -> str:
        type(self).render_calls += 1
        return super().render_trace(provider, findings, duration, **kwargs)


def _config(executable: str = "/opt/prowler/bin/prowler") -> ConfigLoader:
    return cast(
        ConfigLoader,
        ConfigLoader.model_construct(
            openaev=ConfigLoaderOAEV(
                url="http://127.0.0.1:8080", token="runtime-test-token"
            ),
            injector=InjectorConfig(id="prowler-injector", name="Prowler diagnostics"),
            prowler=ProwlerConfig(executable_path=Path(executable)),
        ),
    )


def _aws_content(**overrides: Any) -> dict[str, Any]:
    return {
        "aws_access_key_id": "ACCESS-KEY-CANARY",
        "aws_secret_access_key": "SECRET-CANARY",
        "aws_account_id": "123456789012",
        "aws_region": "eu-west-1",
        "aws_endpoint_url": "https://localhost.localstack.cloud:4566",
        "aws_session_token": "SESSION-CANARY",
        **overrides,
    }


def _message(
    *, inject_id: str = "inject:diagnostic-006", content: Any = None
) -> dict[str, Any]:
    return {
        "injection": {
            "inject_id": inject_id,
            "injector_contract_id": _CONTRACT_ID,
            "inject_content": _aws_content() if content is None else content,
        }
    }


def _runtime(
    *, config: ConfigLoader | None = None, registry: ProwlerContracts | None = None
) -> tuple[ProwlerInjector, Mock]:
    _DiagnosticContract.parse_failure = None
    _DiagnosticContract.render_failure = False
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(_specification(), return_code=0), findings=()
    )
    helper = Mock()
    return (
        ProwlerInjector(
            config or _config(),
            helper,
            registry=registry or ProwlerContracts((_DiagnosticContract,)),
        ),
        helper,
    )


def _error_metadata(helper: Mock) -> dict[str, Any]:
    return helper.injector_logger.local_logger.error.call_args.kwargs["extra"][
        "attributes"
    ]


def _all_logged(helper: Mock) -> str:
    return repr(helper.injector_logger.method_calls) + repr(
        helper.injector_logger.local_logger.method_calls
    )


def _assert_no_raw_canaries(text: str) -> None:
    assert all(canary not in text for canary in _RAW_CANARIES)


def test_listener_reports_identity_contract_count_and_executable_diagnostics(
    tmp_path: Path,
) -> None:
    """Listener INFO answers who and what executable configuration started."""
    executable = tmp_path / "missing" / "prowler"
    injector, helper = _runtime(config=_config(str(executable)))

    injector.start()

    metadata = helper.injector_logger.info.call_args.args[1]
    assert helper.injector_logger.info.call_args.args[0] == _LISTENER_START
    assert metadata == {
        "injector_id": "prowler-injector",
        "injector_name": "Prowler diagnostics",
        "registered_contract_count": 1,
        "configured_executable_path": str(executable),
        "executable_is_absolute": True,
        "executable_exists": False,
        "executable_is_file": False,
        "executable_is_executable": False,
    }


def test_success_lifecycle_has_ordered_correlated_context_and_safe_aws_facts(
    findings: tuple[OpenAevFinding, ...],
) -> None:
    """Every known success stage carries correlation, route, provider, and time."""
    injector, helper = _runtime()
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(_specification(), return_code=0),
        findings=findings,
    )

    injector.process_message(_message())

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
    for item in calls:
        metadata = item.args[1]
        assert metadata["inject_id"] == "inject:diagnostic-006"
        assert 0 <= metadata["elapsed_ms"] <= 86_400_000
        if item.args[0] in {
            _CONTRACT_RESOLVED,
            _ASSESSMENT_VALIDATED,
            _EXECUTION_STARTED,
            _ASSESSMENT_SUCCEEDED,
            _CALLBACK_COMPLETED,
        }:
            assert metadata["contract_id"] == _CONTRACT_ID
            assert metadata["route"] == "aws"
            assert metadata["provider"] == "aws"
    completed = calls[-2].args[1]
    assert completed["finding_count"] == 3
    assert completed["vulnerability_count"] == 1
    assert completed["aws_account_id"] == "123456789012"
    assert completed["aws_region"] == "eu-west-1"
    assert completed["aws_endpoint_origin"] == (
        "https://localhost.localstack.cloud:4566"
    )
    assert completed["aws_session_token_present"] is True
    assert completed["aws_endpoint_override_present"] is True
    assert calls[-1].args[1]["assessment_status"] == "SUCCESS"
    assert calls[-1].args[1]["delivery_status"] == "SUCCESS"
    assert "status" not in calls[-1].args[1]
    assert "attempted_status" not in calls[-1].args[1]
    _assert_no_raw_canaries(_all_logged(helper))


@pytest.mark.parametrize(
    ("reason_code", "message"),
    (
        ("missing_injection", {}),
        ("invalid_injection", {"injection": "RAW-ERROR-MESSAGE-CANARY"}),
        ("missing_inject_id", {"injection": {"inject_id": ""}}),
    ),
)
def test_invalid_messages_use_closed_reason_codes_without_payload(
    reason_code: str, message: dict[str, Any]
) -> None:
    """Malformed envelopes explain the rejection without echoing input."""
    injector, helper = _runtime()

    injector.process_message(message)

    helper.injector_logger.warning.assert_called_once_with(
        _INVALID_MESSAGE, {"reason_code": reason_code}
    )
    _assert_no_raw_canaries(_all_logged(helper))


def test_malformed_correlations_are_distinct_bounded_hashes_without_raw_ids() -> None:
    """Unsafe IDs retain distinguishable correlation without exposing their text."""
    unsafe_ids = (
        "inject\nFORGED-CORRELATION-CANARY-A",
        "x" * 129 + "FORGED-CORRELATION-CANARY-B",
    )
    injector, helper = _runtime()

    observed = []
    for unsafe_id in unsafe_ids:
        helper.reset_mock()
        injector.process_message(_message(inject_id=unsafe_id))
        correlations = {
            item.args[1]["inject_id"] for item in helper.injector_logger.method_calls
        }
        assert len(correlations) == 1
        observed.append(correlations.pop())
        expected = f"invalid:{hashlib.sha256(unsafe_id.encode()).hexdigest()[:16]}"
        assert observed[-1] == expected
        assert len(observed[-1]) == 24
        assert unsafe_id not in _all_logged(helper)
        assert (
            helper.api.inject.execution_callback.call_args.kwargs["inject_id"]
            == unsafe_id
        )

    assert observed[0] != observed[1]


def test_unpaired_surrogate_correlations_are_safely_hashed_and_transported() -> None:
    """Malformed Unicode IDs remain transportable without reaching logs or UI."""
    unsafe_ids = (
        "\ud800UNPAIRED-SURROGATE-CANARY-A",
        "UNPAIRED-SURROGATE-CANARY-B\udfff",
    )
    injector, helper = _runtime()
    _DiagnosticContract.parse_failure = ContractInputError(())

    observed = []
    for unsafe_id in unsafe_ids:
        helper.reset_mock()

        injector.process_message(_message(inject_id=unsafe_id))

        expected = (
            "invalid:"
            + hashlib.sha256(
                unsafe_id.encode("utf-8", errors="surrogatepass")
            ).hexdigest()[:16]
        )
        safe_id = injector._safe_inject_id(unsafe_id)
        assert safe_id == expected
        assert injector._safe_inject_id(unsafe_id) == safe_id
        assert len(safe_id) == 24
        observed.append(safe_id)

        logged = _all_logged(helper)
        callback_call = helper.api.inject.execution_callback.call_args
        callback = callback_call.kwargs["data"]
        assert unsafe_id not in logged
        assert "UNPAIRED-SURROGATE-CANARY" not in logged
        assert unsafe_id not in repr(callback)
        assert "UNPAIRED-SURROGATE-CANARY" not in repr(callback)
        assert safe_id in callback["execution_message"]
        assert callback_call.kwargs["inject_id"] == unsafe_id

    assert observed[0] != observed[1]


def test_input_failure_has_summary_action_issues_and_full_correlation() -> None:
    """Invalid input is actionable without retaining rejected values."""
    injector, helper = _runtime()
    _DiagnosticContract.parse_failure = ContractInputError(
        (ContractInputIssue(("aws_secret_access_key",), "string_too_short"),)
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["inject_id"] == "inject:diagnostic-006"
    assert metadata["contract_id"] == _CONTRACT_ID
    assert metadata["route"] == "aws"
    assert metadata["provider"] == "aws"
    assert metadata["stage"] == "input_validation"
    assert metadata["failure_kind"] == "invalid_input"
    assert metadata["failure_summary"] == "The assessment input was invalid."
    assert metadata["operator_guidance"] == (
        "Correct the listed assessment fields and retry."
    )
    assert metadata["issues"] == [
        {"location": ["aws_secret_access_key"], "type": "string_too_short"}
    ]
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    for line in (
        "Error code: invalid_input",
        "Reason: The assessment input was invalid.",
        "Action: Correct the listed assessment fields and retry.",
        "Inject ID: inject:diagnostic-006",
        f"Contract: {_CONTRACT_ID}",
        "Route: aws",
        "Provider: aws",
        "Issue 1: aws_secret_access_key (string_too_short)",
    ):
        assert line in callback["execution_message"]
    _assert_no_raw_canaries(_all_logged(helper) + callback["execution_message"])


@pytest.mark.parametrize(
    ("error", "return_code", "expected_kind", "expected_evidence"),
    (
        (
            CliEngineError("RAW-ERROR-MESSAGE-CANARY"),
            0,
            "cli_engine_error",
            {},
        ),
        (
            PolicyError("RAW-ERROR-MESSAGE-CANARY"),
            0,
            "policy_rejected",
            {"actual_executable_path": "/opt/prowler/bin/prowler"},
        ),
        (
            PolicyError("RAW-ERROR-MESSAGE-CANARY", kind="policy_evaluation_failed"),
            0,
            "policy_evaluation_failed",
            {"actual_executable_path": "/opt/prowler/bin/prowler"},
        ),
        (
            ExecutionError(
                "RAW-ERROR-MESSAGE-CANARY",
                stdout=b"STDOUT-CONTENT-CANARY",
                stderr=b"STDERR-CONTENT-CANARY!!",
                return_code=23,
            ),
            23,
            "execution_failed",
            {"return_code": 23, "stdout_bytes": 21, "stderr_bytes": 23},
        ),
        (
            ExecutionError(
                "RAW-ERROR-MESSAGE-CANARY",
                kind="timeout",
                stdout=b"STDOUT-CONTENT-CANARY",
                stderr=b"STDERR-CONTENT-CANARY!!",
            ),
            None,
            "timeout",
            {
                "timeout_seconds": 3600.0,
                "stdout_bytes": 21,
                "stderr_bytes": 23,
            },
        ),
        (
            ExecutionError(
                "RAW-ERROR-MESSAGE-CANARY",
                kind="process_start_failed",
                cause="PermissionError",
            ),
            None,
            "process_start_failed",
            {
                "process_start_cause": "PermissionError",
                "actual_executable_path": "/opt/prowler/bin/prowler",
            },
        ),
        (
            ExecutionError(
                "RAW-ERROR-MESSAGE-CANARY",
                kind="unsuccessful_process",
                stdout=b"STDOUT-CONTENT-CANARY",
                stderr=b"STDERR-CONTENT-CANARY!!",
                return_code=31,
            ),
            31,
            "unsuccessful_process",
            {"return_code": 31, "stdout_bytes": 21, "stderr_bytes": 23},
        ),
        (
            ExecutionError(
                "RAW-ERROR-MESSAGE-CANARY",
                kind="output_too_large_after_capture",
                stdout=b"STDOUT-CONTENT-CANARY",
                stderr=b"STDERR-CONTENT-CANARY!!",
            ),
            0,
            "output_too_large_after_capture",
            {
                "maximum_accepted_output_bytes": 104_857_600,
                "stdout_bytes": 21,
                "stderr_bytes": 23,
            },
        ),
        (
            ParsingError(
                "RAW-ERROR-MESSAGE-CANARY",
                stdout=b"STDOUT-CONTENT-CANARY",
                stderr=b"STDERR-CONTENT-CANARY!!",
                context=(("parser", "json"), ("secret", "SECRET-CANARY")),
                cause="RAW-CAUSE-CANARY",
            ),
            0,
            "parsing_failed",
            {"parser_name": "json", "stdout_bytes": 21, "stderr_bytes": 23},
        ),
        (
            CliEngineError("RAW-ERROR-MESSAGE-CANARY", kind="ATTACKER-KIND-CANARY"),
            0,
            "unexpected_failure",
            {},
        ),
    ),
)
def test_engine_failures_have_closed_summary_guidance_and_typed_safe_evidence(
    error: Any,
    return_code: int | None,
    expected_kind: str,
    expected_evidence: dict[str, Any],
) -> None:
    """Known engine failures expose typed counts and facts, never raw internals."""
    injector, helper = _runtime()
    command_result = CommandResult(
        _specification(),
        return_code=return_code,
        stdout=b"COMMAND-RESULT-STDOUT-CANARY",
        stderr=b"COMMAND-RESULT-STDERR-CANARY",
        error=error,
    )
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=command_result, error=error
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["failure_kind"] == expected_kind
    assert metadata["failure_summary"]
    assert metadata["operator_guidance"]
    for key, value in expected_evidence.items():
        assert metadata[key] == value
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    trace = callback["execution_message"]
    assert f"Error code: {expected_kind}" in trace
    assert f"Reason: {metadata['failure_summary']}" in trace
    assert f"Action: {metadata['operator_guidance']}" in trace
    for value in expected_evidence.values():
        assert str(value) in trace
    forbidden = _all_logged(helper) + trace
    _assert_no_raw_canaries(forbidden)
    assert "ATTACKER-KIND-CANARY" not in forbidden
    assert "COMMAND-RESULT-STDOUT-CANARY" not in forbidden
    assert "COMMAND-RESULT-STDERR-CANARY" not in forbidden


def test_unknown_process_start_cause_is_not_exposed() -> None:
    """Only a closed allowlist of process-start cause classes is logged."""
    injector, helper = _runtime()
    error = ExecutionError(
        "RAW-ERROR-MESSAGE-CANARY",
        kind="process_start_failed",
        cause="ATTACKER-CAUSE-CANARY",
    )
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(_specification(), error=error), error=error
    )

    injector.process_message(_message())

    assert "process_start_cause" not in _error_metadata(helper)
    assert "ATTACKER-CAUSE-CANARY" not in _all_logged(helper)


def test_real_resolution_failure_reveals_exact_missing_path_checks_and_correlation(
    tmp_path: Path,
) -> None:
    """A real missing Prowler binary makes the misconfigured path immediately clear."""
    missing = tmp_path / "prowler-install" / "prowler"
    contract_class = type(
        "RealResolutionContract",
        (BaseProwlerContract,),
        {
            "contract_id": _CONTRACT_ID,
            "external_id": "prowler:aws",
            "route_name": "aws",
            "provider": "aws",
            "family": "base",
            "label": "Real resolution",
        },
    )
    injector, helper = _runtime(
        config=_config(str(missing)), registry=ProwlerContracts((contract_class,))
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["failure_kind"] == "resolution_failed"
    assert metadata["inject_id"] == "inject:diagnostic-006"
    assert metadata["configured_executable_path"] == str(missing)
    assert metadata["actual_executable_path"] == str(missing)
    assert metadata["executable_is_absolute"] is True
    assert metadata["executable_exists"] is False
    assert metadata["executable_is_file"] is False
    assert metadata["executable_is_executable"] is False
    trace = helper.api.inject.execution_callback.call_args.kwargs["data"][
        "execution_message"
    ]
    for expected in (
        str(missing),
        "Inject ID: inject:diagnostic-006",
        f"Contract: {_CONTRACT_ID}",
        "Route: aws",
        "Provider: aws",
        "Executable absolute: true",
        "Executable exists: false",
        "Executable regular file: false",
        "Executable executable: false",
    ):
        assert expected in trace


def _write_executable(tmp_path: Path, body: str) -> Path:
    executable = tmp_path / "prowler-test"
    executable.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    executable.chmod(0o700)
    return executable


@pytest.mark.parametrize(
    ("body", "expected_code", "expected_path"),
    (
        ("printf '%s' '{\"broken\"'", "invalid_json", None),
        ("printf '%s' '{}'", "missing_source_path", "finding_info|finding"),
    ),
)
def test_real_ocsf_failures_are_parsing_failures_with_closed_safe_evidence(
    tmp_path: Path,
    body: str,
    expected_code: str,
    expected_path: str | None,
) -> None:
    """Real successful processes retain typed OCSF decode/mapping diagnostics."""
    executable = _write_executable(tmp_path, body)
    injector, helper = _runtime(
        config=_config(str(executable)),
        registry=ProwlerContracts((_RealExecutionContract,)),
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["stage"] == "assessment_execution"
    assert metadata["failure_kind"] == "parsing_failed"
    assert metadata["ocsf_error_code"] == expected_code
    assert metadata["record_index"] == 0
    if expected_path is None:
        assert "source_path" not in metadata
    else:
        assert metadata["source_path"] == expected_path
    assert metadata["configured_executable_path"] == str(executable)
    assert metadata["actual_executable_path"] == str(executable)
    assert metadata["executable_exists"] is True
    assert metadata["executable_is_file"] is True
    assert metadata["executable_is_executable"] is True
    assert metadata["stdout_bytes"] > 0
    assert "broken" not in _all_logged(helper)


def test_existing_nonzero_executable_has_path_stat_and_byte_diagnostics(
    tmp_path: Path,
) -> None:
    """A wrong executable that starts is distinguished from a missing binary."""
    executable = _write_executable(
        tmp_path, "printf '%s' 'STDERR-EXECUTABLE-CANARY' >&2; exit 17"
    )
    injector, helper = _runtime(
        config=_config(str(executable)),
        registry=ProwlerContracts((_RealExecutionContract,)),
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["failure_kind"] == "unsuccessful_process"
    assert metadata["return_code"] == 17
    assert metadata["configured_executable_path"] == str(executable)
    assert metadata["actual_executable_path"] == str(executable)
    assert metadata["executable_exists"] is True
    assert metadata["executable_is_file"] is True
    assert metadata["executable_is_executable"] is True
    assert metadata["stderr_bytes"] == len(b"STDERR-EXECUTABLE-CANARY")
    assert "STDERR-EXECUTABLE-CANARY" not in _all_logged(helper)


def test_forged_ocsf_evidence_uses_closed_sentinels_without_error_text() -> None:
    """Typed OCSF errors cannot smuggle arbitrary code, path, or message text."""
    injector, helper = _runtime()
    error = OcsfMappingError(
        "OCSF-CODE-CANARY",
        "OCSF-MESSAGE-CANARY",
        -99,
        "unmapped.compliance.OCSF-SOURCE-PATH-CANARY",
    )
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(
            _specification(), return_code=0, stdout=b"OCSF-STDOUT-CANARY"
        ),
        error=error,
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["failure_kind"] == "parsing_failed"
    assert metadata["ocsf_error_code"] == "unrecognized"
    assert metadata["record_index"] == 0
    assert metadata["source_path"] == "unrecognized_source_path"
    rendered = _all_logged(helper) + repr(
        helper.api.inject.execution_callback.call_args.kwargs["data"]
    )
    for canary in (
        "OCSF-CODE-CANARY",
        "OCSF-MESSAGE-CANARY",
        "OCSF-SOURCE-PATH-CANARY",
        "OCSF-STDOUT-CANARY",
    ):
        assert canary not in rendered


def test_aws_endpoint_logs_only_normalized_origin_and_never_path() -> None:
    """Endpoint override context cannot retain secret or oversized URL paths."""
    path_canary = "SECRET-ENDPOINT-PATH-CANARY" + "x" * 700
    injector, helper = _runtime()

    injector.process_message(
        _message(
            content=_aws_content(
                aws_endpoint_url=(
                    f"HTTPS://LOCALHOST.localstack.cloud:4566/{path_canary}/nested"
                )
            )
        )
    )

    logged = _all_logged(helper)
    assert path_canary not in logged
    assert "nested" not in logged
    completed = next(
        item.args[1]
        for item in helper.injector_logger.method_calls
        if item.args[0] == _ASSESSMENT_SUCCEEDED
    )
    assert completed["aws_endpoint_override_present"] is True
    assert completed["aws_endpoint_origin"] == (
        "https://localhost.localstack.cloud:4566"
    )
    assert "aws_endpoint_url" not in completed


def test_serialization_failure_does_not_render_and_delivers_one_plain_failure() -> None:
    """Structured output is prepared before the success renderer is invoked."""
    _SerializationFailureContract.render_calls = 0
    injector, helper = _runtime(
        registry=ProwlerContracts((_SerializationFailureContract,))
    )

    injector.process_message(_message())

    assert _SerializationFailureContract.render_calls == 0
    helper.api.inject.execution_callback.assert_called_once()
    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert callback["execution_message"].startswith("Error code: rendering_failed\n")
    assert "execution_output_structured" not in callback
    assert "SERIALIZATION-FAILURE-CANARY" not in (
        _all_logged(helper) + callback["execution_message"]
    )


def test_reception_exception_logs_safe_failure_and_stops_without_callback() -> None:
    """A failed reception is not misreported as an acknowledged assessment."""
    injector, helper = _runtime()
    helper.api.inject.execution_reception.side_effect = RuntimeError(
        "RECEPTION-EXCEPTION-CANARY"
    )

    injector.process_message(_message())

    metadata = _error_metadata(helper)
    assert metadata["stage"] == "reception"
    assert metadata["failure_kind"] == "reception_failed"
    assert metadata["failure_summary"] == (
        "The assessment reception could not be acknowledged."
    )
    assert metadata["operator_guidance"] == (
        "Check OpenAEV connectivity and retry assessment reception."
    )
    helper.api.inject.execution_callback.assert_not_called()
    assert _RECEPTION_ACKNOWLEDGED not in _all_logged(helper)
    assert _CALLBACK_COMPLETED not in _all_logged(helper)
    assert "RECEPTION-EXCEPTION-CANARY" not in _all_logged(helper)


@pytest.mark.parametrize(
    "metadata_method",
    (
        "_success_metadata",
        "_callback_metadata",
        "_context_metadata",
        "_provider_metadata",
        "_bounded_count",
    ),
)
def test_success_delivery_survives_metadata_extraction_failures(
    monkeypatch: pytest.MonkeyPatch, metadata_method: str
) -> None:
    """Best-effort success diagnostics cannot interfere with terminal delivery."""
    injector, helper = _runtime()

    def explode(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise RuntimeError("METADATA-EXTRACTION-CANARY")

    monkeypatch.setattr(ProwlerInjector, metadata_method, explode)

    injector.process_message(_message())

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "SUCCESS"
    assert helper.api.inject.execution_callback.call_count == 1
    assert not helper.injector_logger.local_logger.error.called
    assert "METADATA-EXTRACTION-CANARY" not in _all_logged(helper)


def test_failure_delivery_survives_failure_metadata_extraction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure callback construction is independent from diagnostic metadata."""
    injector, helper = _runtime()
    _DiagnosticContract.parse_failure = RuntimeError("ASSESSMENT-FAILURE-CANARY")

    def explode(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise RuntimeError("FAILURE-METADATA-CANARY")

    monkeypatch.setattr(ProwlerInjector, "_failure_metadata", explode)

    injector.process_message(_message())

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert helper.api.inject.execution_callback.call_count == 1
    assert "FAILURE-METADATA-CANARY" not in _all_logged(helper)


def test_executable_diagnostic_extraction_failure_cannot_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Optional stat evidence is internally no-throw on an assessment failure."""
    injector, helper = _runtime()
    error = ExecutionError(
        "EXECUTION-ERROR-CANARY", kind="unsuccessful_process", return_code=9
    )
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(_specification(), return_code=9, error=error),
        error=error,
    )

    def explode(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise RuntimeError("EXECUTABLE-DIAGNOSTIC-CANARY")

    monkeypatch.setattr(ProwlerInjector, "_executable_diagnostics", explode)

    injector.process_message(_message())

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert callback["execution_status"] == "ERROR"
    assert helper.api.inject.execution_callback.call_count == 1
    assert "EXECUTABLE-DIAGNOSTIC-CANARY" not in _all_logged(helper)


@pytest.mark.parametrize(
    ("route", "provider", "content", "expected"),
    (
        (
            "aws",
            "aws",
            _aws_content(),
            {
                "aws_account_id": "123456789012",
                "aws_region": "eu-west-1",
                "aws_endpoint_origin": "https://localhost.localstack.cloud:4566",
                "aws_session_token_present": True,
                "aws_endpoint_override_present": True,
            },
        ),
        (
            "azure",
            "azure",
            {
                "azure_tenant_id": "TENANT-ID-CANARY",
                "azure_client_id": "CLIENT-ID-CANARY",
                "azure_client_secret": "SECRET-CANARY",
                "azure_subscription_id": "subscription-safe",
                "azure_provider": "AzureCloud",
            },
            {
                "azure_subscription_id": "subscription-safe",
                "azure_provider": "AzureCloud",
                "azure_tenant_id_present": True,
                "azure_client_id_present": True,
                "azure_client_secret_present": True,
            },
        ),
        (
            "gcp",
            "gcp",
            {
                "gcp_service_account_json": "GCP-JSON-CANARY",
                "gcp_project_id": "project-safe",
            },
            {"gcp_project_id": "project-safe", "gcp_credentials_present": True},
        ),
        (
            "kubernetes",
            "kubernetes",
            {
                "kubernetes_kubeconfig": "KUBECONFIG-CANARY",
                "kubernetes_context": "context-safe",
            },
            {
                "kubernetes_context": "context-safe",
                "kubernetes_credentials_present": True,
            },
        ),
    ),
)
def test_success_logs_allowlisted_provider_context_without_credentials(
    route: str, provider: str, content: dict[str, Any], expected: dict[str, Any]
) -> None:
    """Each provider contributes only the approved operational context."""
    identifier = str(stable_contract_id(route))

    def execute(
        self: BaseProwlerContract, config: Any, parsed: Any
    ) -> ContractExecutionOutcome:
        del self, config, parsed
        return ContractExecutionOutcome(
            command_result=CommandResult(_specification(), return_code=0)
        )

    contract_class = type(
        f"Diagnostic{provider.title()}Contract",
        (BaseProwlerContract,),
        {
            "contract_id": identifier,
            "external_id": f"prowler:{route}",
            "route_name": route,
            "provider": provider,
            "family": "base",
            "label": f"Diagnostic {provider}",
            "execute": execute,
        },
    )
    injector, helper = _runtime(registry=ProwlerContracts((contract_class,)))
    message = _message(content=content)
    message["injection"]["injector_contract_id"] = identifier

    injector.process_message(message)

    completed = next(
        item.args[1]
        for item in helper.injector_logger.method_calls
        if item.args[0] == _ASSESSMENT_SUCCEEDED
    )
    for key, value in expected.items():
        assert completed[key] == value
    _assert_no_raw_canaries(_all_logged(helper))


def test_renderer_fallback_contains_same_bounded_diagnostic_lines() -> None:
    """Plain fallback preserves code, reason, action, correlation, and evidence."""
    injector, helper = _runtime()
    _DiagnosticContract.render_failure = True
    error = ExecutionError(
        "RAW-ERROR-MESSAGE-CANARY",
        kind="timeout",
        stdout=b"STDOUT-CONTENT-CANARY",
        stderr=b"STDERR-CONTENT-CANARY!!",
    )
    _DiagnosticContract.outcome = ContractExecutionOutcome(
        command_result=CommandResult(_specification(), error=error), error=error
    )

    injector.process_message(_message())

    callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    trace = callback["execution_message"]
    assert "Error code: timeout" in trace
    assert "Reason:" in trace
    assert "Action:" in trace
    assert "Inject ID: inject:diagnostic-006" in trace
    assert f"Contract: {_CONTRACT_ID}" in trace
    assert "Route: aws" in trace
    assert "Provider: aws" in trace
    assert "Timeout seconds: 3600.0" in trace
    assert "Captured stdout bytes: 21" in trace
    assert "Captured stderr bytes: 23" in trace
    _assert_no_raw_canaries(trace)


def test_callback_failure_logs_attempted_status_and_context_without_exception() -> None:
    """Undelivered callback diagnostics remain verbose only in local logs."""
    injector, helper = _runtime()
    helper.api.inject.execution_callback.side_effect = RuntimeError(
        "RAW-ERROR-MESSAGE-CANARY CALLBACK-PAYLOAD-CANARY"
    )

    injector.process_message(_message())

    assert helper.api.inject.execution_callback.call_count == 1
    error_call = helper.injector_logger.local_logger.error.call_args
    assert error_call.args[0] == _CALLBACK_FAILED
    metadata = error_call.kwargs["extra"]["attributes"]
    assert metadata["failure_kind"] == "callback_failed"
    assert metadata["failure_summary"] == (
        "The terminal OpenAEV callback could not be delivered."
    )
    assert metadata["assessment_status"] == "SUCCESS"
    assert metadata["delivery_status"] == "ERROR"
    assert "status" not in metadata
    assert "attempted_status" not in metadata
    assert metadata["inject_id"] == "inject:diagnostic-006"
    assert metadata["contract_id"] == _CONTRACT_ID
    assert metadata["route"] == "aws"
    assert metadata["provider"] == "aws"
    assert metadata["stage"] == "callback"
    assert error_call.kwargs["exc_info"] is False
    attempted_callback = helper.api.inject.execution_callback.call_args.kwargs["data"]
    assert "callback_failed" not in repr(attempted_callback)
    _assert_no_raw_canaries(_all_logged(helper))
