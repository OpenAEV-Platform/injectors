"""OpenAEV runtime boundary for the Prowler injector."""

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Literal

from pyoaev.helpers import OpenAEVInjectorHelper
from pyoaev.utils import AppLogger

from prowler._core.cli_engine import CliEngineError, ExecutionError, ParsingError
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, ProwlerContracts
from prowler.contracts.base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
)
from prowler.models import ConfigLoader
from prowler.models.provider_inputs import ProviderInput

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
_CALLBACK_FAILED = "[PROWLER_INJECTOR] - Assessment callback failed"

_ALLOWED_CLI_FAILURE_KINDS = frozenset(
    {
        "cli_engine_error",
        "policy_rejected",
        "policy_evaluation_failed",
        "resolution_failed",
        "execution_failed",
        "timeout",
        "process_start_failed",
        "unsuccessful_process",
        "output_too_large_after_capture",
        "parsing_failed",
    }
)
_ALLOWED_ISSUE_LOCATIONS = frozenset(
    {
        "provider",
        "aws",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_account_id",
        "aws_region",
        "aws_endpoint_url",
        "aws_session_token",
        "azure",
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "azure_provider",
        "gcp",
        "gcp_service_account_json",
        "gcp_project_id",
        "kubernetes",
        "kubernetes_kubeconfig",
        "kubernetes_context",
    }
)
_ALLOWED_ISSUE_TYPES = frozenset(
    {
        "extra_forbidden",
        "literal_error",
        "missing",
        "string_too_long",
        "string_too_short",
        "string_pattern_mismatch",
        "string_type",
        "union_tag_invalid",
        "union_tag_not_found",
        "value_error",
    }
)
_ISSUE_LOCATION_SENTINEL = "unrecognized_field"
_ISSUE_TYPE_SENTINEL = "invalid"
_MAX_LOG_ISSUES = 16
_MAX_ISSUE_LOCATION_DEPTH = 3
_MAX_ISSUE_LOCATION_LENGTH = 64
_MAX_LOG_COUNT = 1_000_000
_MAX_LOG_DURATION_SECONDS = 86_400
_MAX_ELAPSED_MS = 86_400_000
_MAX_BYTE_COUNT = 1_000_000_000
_MAX_SAFE_TEXT = 512
_INVALID_INJECT_ID = "invalid-inject-id"
_INJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_PROCESS_START_CAUSES = frozenset(
    {
        "FileNotFoundError",
        "PermissionError",
        "IsADirectoryError",
        "NotADirectoryError",
        "OSError",
    }
)
_PARSER_NAMES = frozenset({"raw", "text", "json", "lines", "regex"})

_GENERIC_INPUT_GUIDANCE = "Correct the listed assessment fields and retry."
_GUIDANCE_BY_FAILURE_KIND = {
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
    "invalid_input": _GENERIC_INPUT_GUIDANCE,
    "rendering_failed": "Review injector trace rendering configuration and retry.",
    "callback_failed": "Check OpenAEV connectivity and retry callback delivery.",
    "unexpected_failure": "Review injector configuration and retry the assessment.",
}
_SUMMARY_BY_FAILURE_KIND = {
    "cli_engine_error": "The Prowler execution engine rejected the assessment.",
    "policy_rejected": "The assessment did not satisfy the execution policy.",
    "policy_evaluation_failed": "The execution policy could not be evaluated.",
    "resolution_failed": "The configured Prowler executable could not be resolved.",
    "execution_failed": "Prowler execution failed before a successful result.",
    "timeout": "Prowler did not finish within the injector timeout.",
    "process_start_failed": "The Prowler process could not be started.",
    "unsuccessful_process": "Prowler exited with an unsuccessful return code.",
    "output_too_large_after_capture": (
        "Captured Prowler output exceeded the injector safety limit."
    ),
    "parsing_failed": "Captured Prowler output could not be parsed safely.",
    "invalid_input": "The assessment input was invalid.",
    "rendering_failed": "The OpenAEV execution trace could not be rendered.",
    "callback_failed": "The terminal OpenAEV callback could not be delivered.",
    "unexpected_failure": "The assessment failed at an unexpected internal boundary.",
}
_ISSUE_FIELD_LABELS = {
    "provider": "Provider",
    "aws_access_key_id": "AWS access key ID",
    "aws_secret_access_key": "AWS secret access key",
    "aws_account_id": "AWS account ID",
    "aws_region": "AWS region",
    "aws_endpoint_url": "AWS endpoint URL",
    "aws_session_token": "AWS session token",
    "azure_tenant_id": "Azure tenant ID",
    "azure_client_id": "Azure client ID",
    "azure_client_secret": "Azure client secret",
    "azure_subscription_id": "Azure subscription ID",
    "azure_provider": "Azure provider",
    "gcp_service_account_json": "GCP service account JSON",
    "gcp_project_id": "GCP project ID",
    "kubernetes_kubeconfig": "Kubernetes kubeconfig",
    "kubernetes_context": "Kubernetes context",
}
_ISSUE_TYPE_PHRASES = {
    "extra_forbidden": "is not accepted.",
    "literal_error": "has an invalid selection.",
    "missing": "is required.",
    "string_pattern_mismatch": "has an invalid format.",
    "string_too_long": "is too long.",
    "string_too_short": "is too short.",
    "string_type": "must be text.",
    "union_tag_invalid": "has an invalid provider selection.",
    "union_tag_not_found": "requires a provider selection.",
    "value_error": "has an invalid value.",
}


@dataclass(frozen=True)
class _FailurePresentation:
    """One closed classification shared by logs and OpenAEV presentation."""

    stage: str
    failure_kind: str
    failure_summary: str
    operator_guidance: str
    return_code: int | None = None
    configured_executable_path: str | None = None
    actual_executable_path: str | None = None
    executable_is_absolute: bool | None = None
    executable_exists: bool | None = None
    executable_is_file: bool | None = None
    executable_is_executable: bool | None = None
    process_start_cause: str | None = None
    timeout_seconds: float | None = None
    maximum_accepted_output_bytes: int | None = None
    parser_name: str | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    issues: tuple[dict[str, object], ...] | None = None
    issues_omitted: int = 0
    issues_truncated: bool = False


class ProwlerInjector:
    """Register the foundation injector without assessment contracts."""

    def __init__(
        self,
        config: ConfigLoader,
        helper: OpenAEVInjectorHelper,
        *,
        registry: ProwlerContracts = DEFAULT_PROWLER_CONTRACTS,
    ) -> None:
        """Initialize the injector with its configuration and helper."""
        self.config = config
        self.helper = helper
        self.registry = registry

    def start(self) -> None:
        """Start the injector listener after zero-contract registration."""
        raw_executable = str(self.config.prowler.executable_path)
        executable = self._safe_text(raw_executable)
        metadata: dict[str, object] = {
            "injector_id": self._safe_text(str(self.config.injector.id)),
            "injector_name": self._safe_text(str(self.config.injector.name)),
            "registered_contract_count": self._bounded_count(len(self.registry)),
            "configured_executable_path": executable,
        }
        metadata.update(self._executable_diagnostics(raw_executable))
        self._log("info", _LISTENER_START, metadata)
        self.config.to_daemon_config(self.registry)
        self.helper.listen(message_callback=self.process_message)

    def process_message(self, data: dict[str, object]) -> None:
        """Receive, validate, dispatch once, and send one terminal callback."""
        started = monotonic()
        injection = data.get("injection")
        if not isinstance(injection, Mapping):
            reason = (
                "missing_injection" if "injection" not in data else "invalid_injection"
            )
            self._log("warning", _INVALID_MESSAGE, {"reason_code": reason})
            return
        inject_id = injection.get("inject_id")
        if not isinstance(inject_id, str) or not inject_id:
            self._log("warning", _INVALID_MESSAGE, {"reason_code": "missing_inject_id"})
            return
        safe_inject_id = self._safe_inject_id(inject_id)
        contract: BaseProwlerContract | None = None
        provider: ProviderInput | None = None
        failure_metadata: dict[str, object] | None = None
        success_metadata: dict[str, object] | None = None
        stage = "message_reception"
        self._log(
            "info",
            _ASSESSMENT_RECEIVED,
            self._context_metadata(started, safe_inject_id, stage=stage),
        )
        try:
            self.helper.api.inject.execution_reception(
                inject_id=inject_id, data={"tracking_total_count": 1}
            )
            stage = "reception_acknowledged"
            self._log(
                "debug",
                _RECEPTION_ACKNOWLEDGED,
                self._context_metadata(started, safe_inject_id, stage=stage),
            )
            stage = "contract_resolution"
            contract_id = self._contract_id(injection)
            contract = self.registry.resolve(contract_id)
            self._log(
                "debug",
                _CONTRACT_RESOLVED,
                self._context_metadata(
                    started, safe_inject_id, stage=stage, contract=contract
                ),
            )
            stage = "input_validation"
            content = injection.get("inject_content")
            if not isinstance(content, Mapping):
                raise ContractInputError(())
            provider = contract.parse_input(content)
            self._log(
                "debug",
                _ASSESSMENT_VALIDATED,
                self._context_metadata(
                    started,
                    safe_inject_id,
                    stage=stage,
                    contract=contract,
                    provider=provider,
                ),
            )
            stage = "assessment_execution"
            self._log(
                "info",
                _EXECUTION_STARTED,
                self._context_metadata(
                    started,
                    safe_inject_id,
                    stage=stage,
                    contract=contract,
                    provider=provider,
                ),
            )
            outcome = contract.execute(self.config.prowler, provider)
            if outcome.error is not None or outcome.command_result.return_code != 0:
                duration = int(monotonic() - started)
                failure = self._classify_assessment_failure(
                    outcome, configured_executable=self.config.prowler.executable_path
                )
                callback = {
                    "execution_message": self._render_safe_error(
                        contract,
                        duration,
                        failure,
                        inject_id=safe_inject_id,
                    ),
                    "execution_status": "ERROR",
                    "execution_duration": duration,
                    "execution_action": "complete",
                }
                failure_metadata = self._failure_metadata(
                    started,
                    safe_inject_id,
                    contract,
                    provider,
                    failure,
                )
            else:
                stage = "output_preparation"
                duration = int(monotonic() - started)
                try:
                    execution_message = contract.render_trace(
                        provider, outcome.findings, duration
                    )
                except Exception:
                    failure = self._classify_internal_failure(
                        stage="output_preparation",
                        failure_kind="rendering_failed",
                    )
                    callback = {
                        "execution_message": self._plain_safe_error(
                            failure,
                            inject_id=safe_inject_id,
                            contract=contract,
                        ),
                        "execution_status": "ERROR",
                        "execution_duration": duration,
                        "execution_action": "complete",
                    }
                    failure_metadata = self._failure_metadata(
                        started,
                        safe_inject_id,
                        contract,
                        provider,
                        failure,
                    )
                else:
                    callback = {
                        "execution_message": execution_message,
                        "execution_output_structured": json.dumps(
                            contract.output_payload(outcome.findings),
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                        "execution_status": "SUCCESS",
                        "execution_duration": duration,
                        "execution_action": "complete",
                    }
                    success_metadata = self._success_metadata(
                        started,
                        safe_inject_id,
                        contract,
                        provider,
                        outcome,
                    )
        except Exception as error:
            duration = int(monotonic() - started)
            failure = self._classify_exception_failure(stage, error)
            callback = {
                "execution_message": self._render_safe_error(
                    contract,
                    duration,
                    failure,
                    inject_id=safe_inject_id,
                ),
                "execution_status": "ERROR",
                "execution_duration": duration,
                "execution_action": "complete",
            }
            failure_metadata = self._failure_metadata(
                started,
                safe_inject_id,
                contract,
                provider,
                failure,
            )

        if failure_metadata is not None:
            self._log_error(_ASSESSMENT_FAILED, failure_metadata)
        elif success_metadata is not None:
            self._log("info", _ASSESSMENT_SUCCEEDED, success_metadata)
        try:
            self.helper.api.inject.execution_callback(
                inject_id=inject_id, data=callback
            )
        except Exception:
            failure = self._classify_internal_failure(
                stage="callback", failure_kind="callback_failed"
            )
            self._log_error(
                _CALLBACK_FAILED,
                self._failure_metadata(
                    started,
                    safe_inject_id,
                    contract,
                    provider,
                    failure,
                    attempted_status=callback["execution_status"],
                ),
            )
            return
        self._log(
            "debug",
            _CALLBACK_COMPLETED,
            self._callback_metadata(
                started,
                safe_inject_id,
                contract,
                provider,
                callback["execution_status"],
            ),
        )

    def _log(
        self,
        level: Literal["debug", "info", "warning"],
        message: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """Emit a non-error lifecycle event without affecting assessment flow."""
        try:
            log_method = getattr(self.helper.injector_logger, level)
            if metadata is None:
                log_method(message)
            else:
                log_method(message, metadata)
        except Exception:
            return

    def _log_error(self, message: str, metadata: dict[str, object]) -> None:
        """Bypass the pinned helper's forced traceback behavior for ERROR only."""
        try:
            self.helper.injector_logger.local_logger.error(
                message,
                exc_info=False,
                extra=AppLogger.prepare_meta(metadata),
            )
        except Exception:
            return

    @classmethod
    def _success_metadata(
        cls,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract,
        provider: ProviderInput,
        outcome: ContractExecutionOutcome,
    ) -> dict[str, object]:
        """Summarize a successful result without retaining finding content."""
        metadata = cls._context_metadata(
            started,
            inject_id,
            stage="assessment_completion",
            contract=contract,
            provider=provider,
        )
        metadata.update(
            status="SUCCESS",
            finding_count=cls._bounded_count(len(outcome.findings)),
            vulnerability_count=cls._bounded_count(
                sum(
                    finding.expectation_result == "FAILED"
                    for finding in outcome.findings
                )
            ),
        )
        return metadata

    @classmethod
    def _classify_assessment_failure(
        cls,
        outcome: ContractExecutionOutcome,
        *,
        configured_executable: Path,
    ) -> _FailurePresentation:
        """Classify one returned assessment failure exactly once."""
        error = outcome.error
        result = outcome.command_result
        specification = result.specification
        failure_kind = "unexpected_failure"
        if (
            isinstance(error, CliEngineError)
            and error.kind in _ALLOWED_CLI_FAILURE_KINDS
        ):
            failure_kind = error.kind
        return_code = error.return_code if isinstance(error, ExecutionError) else None
        if return_code is None:
            return_code = result.return_code
        safe_return_code = (
            cls._bounded_return_code(return_code)
            if isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and return_code != 0
            else None
        )
        configured_path: str | None = None
        actual_path: str | None = None
        executable_is_absolute: bool | None = None
        executable_exists: bool | None = None
        executable_is_file: bool | None = None
        executable_is_executable: bool | None = None
        process_start_cause: str | None = None
        timeout_seconds: float | None = None
        maximum_accepted_output_bytes: int | None = None
        parser_name: str | None = None
        stdout_bytes: int | None = None
        stderr_bytes: int | None = None
        if failure_kind in {
            "policy_rejected",
            "policy_evaluation_failed",
            "resolution_failed",
            "process_start_failed",
        }:
            configured_path = cls._safe_text(str(configured_executable))
            actual_path = cls._safe_text(specification.executable)
            diagnostics = cls._executable_diagnostics(specification.executable)
            executable_is_absolute = diagnostics["executable_is_absolute"] is True
            executable_exists = diagnostics["executable_exists"] is True
            executable_is_file = diagnostics["executable_is_file"] is True
            executable_is_executable = diagnostics["executable_is_executable"] is True
        if failure_kind in {
            "execution_failed",
            "timeout",
            "unsuccessful_process",
            "output_too_large_after_capture",
            "parsing_failed",
        }:
            stdout, stderr = cls._captured_bytes(error, result)
            stdout_bytes = cls._bounded_bytes(len(stdout))
            stderr_bytes = cls._bounded_bytes(len(stderr))
        if failure_kind == "process_start_failed" and isinstance(error, ExecutionError):
            if error.cause in _PROCESS_START_CAUSES:
                process_start_cause = error.cause
        if failure_kind == "timeout":
            timeout_seconds = cls._bounded_seconds(specification.timeout_seconds)
        if failure_kind == "output_too_large_after_capture":
            maximum_accepted_output_bytes = cls._bounded_bytes(
                specification.maximum_accepted_output_bytes
            )
        if failure_kind == "parsing_failed":
            selected_parser = specification.output.parser.lower()
            parser_name = (
                selected_parser if selected_parser in _PARSER_NAMES else "unrecognized"
            )
        if failure_kind not in {"execution_failed", "unsuccessful_process"}:
            safe_return_code = None
        return _FailurePresentation(
            stage="assessment_execution",
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            return_code=safe_return_code,
            configured_executable_path=configured_path,
            actual_executable_path=actual_path,
            executable_is_absolute=executable_is_absolute,
            executable_exists=executable_exists,
            executable_is_file=executable_is_file,
            executable_is_executable=executable_is_executable,
            process_start_cause=process_start_cause,
            timeout_seconds=timeout_seconds,
            maximum_accepted_output_bytes=maximum_accepted_output_bytes,
            parser_name=parser_name,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )

    @staticmethod
    def _captured_bytes(error: object, result: object) -> tuple[bytes, bytes]:
        """Use typed engine error bytes, falling back to the result envelope."""
        if isinstance(error, (ExecutionError, ParsingError)):
            return error.stdout, error.stderr
        stdout = getattr(result, "stdout", b"")
        stderr = getattr(result, "stderr", b"")
        return (
            stdout if isinstance(stdout, bytes) else b"",
            stderr if isinstance(stderr, bytes) else b"",
        )

    @classmethod
    def _classify_exception_failure(
        cls, stage: str, error: Exception
    ) -> _FailurePresentation:
        """Classify a raised failure without reading its text or representation."""
        if stage == "input_validation" and isinstance(error, ContractInputError):
            issues, omitted, truncated = cls._safe_input_issues(error)
            return _FailurePresentation(
                stage=stage,
                failure_kind="invalid_input",
                failure_summary=_SUMMARY_BY_FAILURE_KIND["invalid_input"],
                operator_guidance=cls._input_guidance(
                    error, issues, truncated=truncated
                ),
                issues=tuple(issues),
                issues_omitted=omitted,
                issues_truncated=truncated,
            )
        return _FailurePresentation(
            stage=stage,
            failure_kind="unexpected_failure",
            failure_summary=_SUMMARY_BY_FAILURE_KIND["unexpected_failure"],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND["unexpected_failure"],
        )

    @staticmethod
    def _classify_internal_failure(
        *,
        stage: Literal["output_preparation", "callback"],
        failure_kind: Literal["rendering_failed", "callback_failed"],
    ) -> _FailurePresentation:
        """Classify one fixed injector-owned failure."""
        return _FailurePresentation(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
        )

    @classmethod
    def _failure_metadata(
        cls,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        failure: _FailurePresentation,
        *,
        attempted_status: object | None = None,
    ) -> dict[str, object]:
        """Project one closed failure presentation into safe log metadata."""
        metadata = cls._context_metadata(
            started,
            inject_id,
            stage=failure.stage,
            contract=contract,
            provider=provider,
        )
        metadata.update(
            status="ERROR",
            failure_kind=failure.failure_kind,
            failure_summary=failure.failure_summary,
            operator_guidance=failure.operator_guidance,
        )
        if attempted_status is not None:
            metadata["attempted_status"] = (
                "SUCCESS" if attempted_status == "SUCCESS" else "ERROR"
            )
        if failure.return_code is not None:
            metadata["return_code"] = failure.return_code
        for key in (
            "configured_executable_path",
            "actual_executable_path",
            "executable_is_absolute",
            "executable_exists",
            "executable_is_file",
            "executable_is_executable",
            "process_start_cause",
            "timeout_seconds",
            "maximum_accepted_output_bytes",
            "parser_name",
            "stdout_bytes",
            "stderr_bytes",
        ):
            value = getattr(failure, key)
            if value is not None:
                metadata[key] = value
        if failure.issues is not None:
            metadata["issues"] = list(failure.issues)
        if failure.issues_omitted:
            metadata["issues_omitted"] = failure.issues_omitted
        if failure.issues_truncated:
            metadata["issues_truncated"] = True
        return metadata

    @staticmethod
    def _input_guidance(
        error: ContractInputError,
        issues: list[dict[str, object]],
        *,
        truncated: bool,
    ) -> str:
        """Select one sentence only from normalized, trusted issue structure."""
        if not error.issues_are_trusted or truncated or not issues:
            return _GENERIC_INPUT_GUIDANCE
        selected = issues[0]
        location = selected.get("location")
        error_type = selected.get("type")
        if not isinstance(location, list) or not isinstance(error_type, str):
            return _GENERIC_INPUT_GUIDANCE
        if any(
            not isinstance(segment, str) or segment == _ISSUE_LOCATION_SENTINEL
            for segment in location
        ):
            return _GENERIC_INPUT_GUIDANCE
        if error_type == _ISSUE_TYPE_SENTINEL:
            return _GENERIC_INPUT_GUIDANCE
        if (
            tuple(location[-2:]) == ("aws", "aws_account_id")
            and error_type == "string_pattern_mismatch"
        ):
            return "AWS account ID must contain exactly 12 ASCII digits."
        if not location:
            return _GENERIC_INPUT_GUIDANCE
        label = _ISSUE_FIELD_LABELS.get(location[-1])
        phrase = _ISSUE_TYPE_PHRASES.get(error_type)
        if label is None or phrase is None:
            return _GENERIC_INPUT_GUIDANCE
        guidance = f"{label} {phrase}"
        return guidance if len(guidance) <= 100 else _GENERIC_INPUT_GUIDANCE

    @classmethod
    def _safe_input_issues(
        cls, error: ContractInputError
    ) -> tuple[list[dict[str, object]], int, bool]:
        """Bound and normalize validation structure before it reaches logging."""
        selected = error.issues[:_MAX_LOG_ISSUES]
        omitted = cls._bounded_count(len(error.issues) - len(selected))
        truncated = omitted > 0
        issues: list[dict[str, object]] = []
        for issue in selected:
            location: list[str] = []
            for segment in issue.location[:_MAX_ISSUE_LOCATION_DEPTH]:
                if (
                    isinstance(segment, str)
                    and len(segment) <= _MAX_ISSUE_LOCATION_LENGTH
                    and segment in _ALLOWED_ISSUE_LOCATIONS
                ):
                    location.append(segment)
                else:
                    location.append(_ISSUE_LOCATION_SENTINEL)
                    truncated = True
            if len(issue.location) > _MAX_ISSUE_LOCATION_DEPTH:
                truncated = True
            error_type = issue.error_type
            if error_type not in _ALLOWED_ISSUE_TYPES:
                error_type = _ISSUE_TYPE_SENTINEL
                truncated = True
            issues.append({"location": location, "type": error_type})
        return issues, omitted, truncated

    @classmethod
    def _callback_metadata(
        cls,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        status: object,
    ) -> dict[str, object]:
        """Describe callback completion with attempted terminal status and context."""
        metadata = cls._context_metadata(
            started,
            inject_id,
            stage="callback",
            contract=contract,
            provider=provider,
        )
        metadata.update(
            status="SUCCESS" if status == "SUCCESS" else "ERROR",
            attempted_status="SUCCESS" if status == "SUCCESS" else "ERROR",
        )
        return metadata

    @classmethod
    def _context_metadata(
        cls,
        started: float,
        inject_id: str,
        *,
        stage: str,
        contract: BaseProwlerContract | None = None,
        provider: ProviderInput | None = None,
    ) -> dict[str, object]:
        """Build the common bounded lifecycle correlation envelope."""
        metadata: dict[str, object] = {
            "inject_id": inject_id,
            "stage": stage,
            "elapsed_ms": cls._elapsed_ms(started),
        }
        if contract is not None:
            metadata.update(
                contract_id=cls._safe_text(contract.contract_id),
                route=cls._safe_text(contract.route_name),
                provider=contract.provider,
            )
        if provider is not None:
            metadata.update(cls._provider_metadata(provider))
        return metadata

    @classmethod
    def _provider_metadata(cls, provider: ProviderInput) -> dict[str, object]:
        """Return approved provider facts without reading credential values."""
        from prowler.models.provider_inputs import (
            AwsProviderInput,
            AzureProviderInput,
            GcpProviderInput,
            KubernetesProviderInput,
        )

        if isinstance(provider, AwsProviderInput):
            metadata: dict[str, object] = {
                "aws_account_id": cls._safe_text(provider.aws_account_id),
                "aws_region": cls._safe_text(provider.aws_region),
                "aws_session_token_present": provider.aws_session_token is not None,
                "aws_endpoint_override_present": provider.aws_endpoint_url is not None,
            }
            if provider.aws_endpoint_url is not None:
                metadata["aws_endpoint_url"] = cls._safe_text(provider.aws_endpoint_url)
            return metadata
        if isinstance(provider, AzureProviderInput):
            return {
                "azure_subscription_id": cls._safe_text(provider.azure_subscription_id),
                "azure_provider": cls._safe_text(provider.azure_provider),
                "azure_tenant_id_present": True,
                "azure_client_id_present": True,
                "azure_client_secret_present": True,
            }
        if isinstance(provider, GcpProviderInput):
            return {
                "gcp_project_id": cls._safe_text(provider.gcp_project_id),
                "gcp_credentials_present": True,
            }
        if isinstance(provider, KubernetesProviderInput):
            return {
                "kubernetes_context": cls._safe_text(provider.kubernetes_context),
                "kubernetes_credentials_present": True,
            }
        return {}

    @staticmethod
    def _safe_inject_id(value: str) -> str:
        """Allow only bounded log-safe correlation syntax."""
        return value if _INJECT_ID_PATTERN.fullmatch(value) else _INVALID_INJECT_ID

    @staticmethod
    def _safe_text(value: str) -> str:
        """Bound explicitly approved operational text."""
        printable = "".join(
            character if character.isprintable() else "?" for character in value
        )
        if len(printable) <= _MAX_SAFE_TEXT:
            return printable
        return f"{printable[: _MAX_SAFE_TEXT - 3]}..."

    @staticmethod
    def _executable_diagnostics(executable: str) -> dict[str, object]:
        """Inspect one approved executable path without raising into execution."""
        path = Path(executable)
        try:
            is_absolute = path.is_absolute()
            exists = path.exists()
            is_file = path.is_file()
            is_executable = is_file and os.access(path, os.X_OK)
        except OSError:
            is_absolute = path.is_absolute()
            exists = False
            is_file = False
            is_executable = False
        return {
            "executable_is_absolute": is_absolute,
            "executable_exists": exists,
            "executable_is_file": is_file,
            "executable_is_executable": is_executable,
        }

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        """Clamp monotonic elapsed time to the lifecycle metadata domain."""
        return max(0, min(int((monotonic() - started) * 1000), _MAX_ELAPSED_MS))

    @staticmethod
    def _bounded_bytes(value: int) -> int:
        """Clamp evidence byte counts to a closed non-negative domain."""
        return max(0, min(value, _MAX_BYTE_COUNT))

    @staticmethod
    def _bounded_return_code(value: int) -> int:
        """Clamp process return-code evidence to a small signed domain."""
        return max(-65_535, min(value, 65_535))

    @staticmethod
    def _bounded_seconds(value: float) -> float:
        """Clamp configured timeout evidence without inventing precision."""
        return max(0.0, min(float(value), float(_MAX_LOG_DURATION_SECONDS)))

    @staticmethod
    def _bounded_count(value: int) -> int:
        """Clamp count metadata to a small non-negative numeric domain."""
        return max(0, min(value, _MAX_LOG_COUNT))

    @staticmethod
    def _bounded_duration(value: int) -> int:
        """Clamp duration metadata without changing callback duration behavior."""
        return max(0, min(value, _MAX_LOG_DURATION_SECONDS))

    @classmethod
    def _plain_safe_error(
        cls,
        failure: _FailurePresentation,
        *,
        inject_id: str,
        contract: BaseProwlerContract | None,
    ) -> str:
        """Render bounded diagnostic lines shared by Rich and plain fallback."""
        lines = [
            f"Error code: {failure.failure_kind}",
            f"Reason: {failure.failure_summary}",
            f"Action: {failure.operator_guidance}",
            f"Inject ID: {inject_id}",
        ]
        if contract is not None:
            lines.extend(
                (
                    f"Contract: {cls._safe_text(contract.contract_id)}",
                    f"Route: {cls._safe_text(contract.route_name)}",
                    f"Provider: {contract.provider}",
                )
            )
        labels = (
            ("configured_executable_path", "Configured executable"),
            ("actual_executable_path", "Actual executable"),
            ("executable_is_absolute", "Executable absolute"),
            ("executable_exists", "Executable exists"),
            ("executable_is_file", "Executable regular file"),
            ("executable_is_executable", "Executable executable"),
            ("process_start_cause", "Process start cause"),
            ("timeout_seconds", "Timeout seconds"),
            ("maximum_accepted_output_bytes", "Accepted output byte limit"),
            ("parser_name", "Parser"),
            ("stdout_bytes", "Captured stdout bytes"),
            ("stderr_bytes", "Captured stderr bytes"),
            ("return_code", "Return code"),
        )
        for key, label in labels:
            value = getattr(failure, key)
            if value is not None:
                rendered = str(value).lower() if isinstance(value, bool) else str(value)
                lines.append(f"{label}: {rendered}")
        if failure.issues is not None:
            for index, issue in enumerate(failure.issues, 1):
                location = issue.get("location")
                error_type = issue.get("type")
                if isinstance(location, list) and isinstance(error_type, str):
                    field = ".".join(part for part in location if isinstance(part, str))
                    lines.append(f"Issue {index}: {field or 'input'} ({error_type})")
        if failure.issues_omitted:
            lines.append(f"Issues omitted: {failure.issues_omitted}")
        if failure.issues_truncated:
            lines.append("Issues truncated: true")
        return "\n".join(lines)

    @classmethod
    def _render_safe_error(
        cls,
        contract: BaseProwlerContract | None,
        duration: int,
        failure: _FailurePresentation,
        *,
        inject_id: str,
    ) -> str:
        """Render once, falling back to the same closed code and guidance."""
        safe_error = cls._plain_safe_error(
            failure, inject_id=inject_id, contract=contract
        )
        if contract is None:
            return safe_error
        try:
            return contract.render_trace(
                None,
                (),
                duration,
                is_error=True,
                error_message=safe_error,
            )
        except Exception:
            return safe_error

    @staticmethod
    def _contract_id(injection: Mapping[str, object]) -> str:
        """Extract one unambiguous ID from both observed message shapes."""
        primary = injection.get("injector_contract_id")
        nested = injection.get("inject_injector_contract")
        if isinstance(nested, Mapping):
            nested_id = nested.get("injector_contract_id")
            if primary is not None and nested_id is not None and primary != nested_id:
                raise ValueError("conflicting Prowler contract identifiers")
            if primary is None:
                primary = nested_id
        converted = injection.get("convertedContent")
        fallback = (
            converted.get("contract_id") if isinstance(converted, Mapping) else None
        )
        if primary is not None and fallback is not None and primary != fallback:
            raise ValueError("conflicting Prowler contract identifiers")
        selected = primary if primary is not None else fallback
        if not isinstance(selected, str) or not selected:
            raise ValueError("Prowler contract identifier is missing")
        return selected
