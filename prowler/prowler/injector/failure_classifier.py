"""Classify assessment failures into one closed, safe presentation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from prowler._core.cli_engine import CliEngineError, ExecutionError, ParsingError
from prowler._core.prowler_client import (
    OutputArtifactError,
    OutputWorkspaceCleanupError,
    OutputWorkspacePreparationError,
)
from prowler.contracts.base import ContractExecutionOutcome, ContractInputError
from prowler.injector.failure_taxonomy import (
    _ALLOWED_CLI_FAILURE_KINDS,
    _ALLOWED_ISSUE_LOCATIONS,
    _ALLOWED_ISSUE_TYPES,
    _ARTIFACT_FAILURE_KIND,
    _GENERIC_INPUT_GUIDANCE,
    _GUIDANCE_BY_FAILURE_KIND,
    _ISSUE_FIELD_LABELS,
    _ISSUE_LOCATION_SENTINEL,
    _ISSUE_TYPE_PHRASES,
    _ISSUE_TYPE_SENTINEL,
    _MAX_ISSUE_LOCATION_DEPTH,
    _MAX_ISSUE_LOCATION_LENGTH,
    _MAX_LOG_ISSUES,
    _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES,
    _OCSF_CODE_SENTINEL,
    _OCSF_DECODE_CODES,
    _OCSF_INDEXED_SOURCE_PATH_PATTERN,
    _OCSF_MAPPING_CODES,
    _OCSF_SOURCE_PATH_SENTINEL,
    _OCSF_SOURCE_PATHS,
    _PARSER_NAMES,
    _PROCESS_START_CAUSES,
    _SUMMARY_BY_FAILURE_KIND,
    _ArtifactFailure,
    _AssessmentFailure,
    _ExecutableEvidence,
    _FailurePresentation,
    _InputValidationFailure,
    _InternalFailure,
    _OcsfDecodeFailure,
    _UnexpectedFailure,
)
from prowler.models.findings import OcsfDecodeError, OcsfMappingError

if TYPE_CHECKING:
    from prowler.injector.lifecycle_metadata import LifecycleMetadataBuilder
    from prowler.injector.openaev_prowler import ProwlerInjector


class FailureClassifier:
    """Produce the one closed failure presentation per assessment failure."""

    def __init__(self, facade: ProwlerInjector, meta: LifecycleMetadataBuilder) -> None:
        """Attach the facade and metadata builder for shared routing."""
        self._facade = facade
        self._meta = meta

    def _classify_assessment_failure(
        self,
        outcome: ContractExecutionOutcome,
        *,
        configured_executable: object,
    ) -> _FailurePresentation:
        """Classify one returned assessment failure exactly once."""
        error = outcome.error
        result = outcome.command_result
        try:
            specification: object | None = result.specification
        except Exception:
            specification = None
        failure_kind = "unexpected_failure"
        if isinstance(error, (OcsfDecodeError, OcsfMappingError)):
            failure_kind = "parsing_failed"
        elif (
            isinstance(error, CliEngineError)
            and error.kind in _ALLOWED_CLI_FAILURE_KINDS
        ):
            failure_kind = error.kind
        return_code = error.return_code if isinstance(error, ExecutionError) else None
        if return_code is None:
            return_code = result.return_code
        safe_return_code = (
            self._meta._bounded_return_code(return_code)
            if isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and return_code != 0
            else None
        )
        executable = self._executable_evidence(configured_executable, specification)
        process_start_cause: str | None = None
        timeout_seconds: float | None = None
        maximum_accepted_output_bytes: int | None = None
        parser_name: str | None = None
        stdout_bytes: int | None = None
        stderr_bytes: int | None = None
        ocsf_error_code: str | None = None
        record_index: int | None = None
        source_path: str | None = None
        if failure_kind in {
            "execution_failed",
            "timeout",
            "unsuccessful_process",
            "output_too_large_after_capture",
            "parsing_failed",
        }:
            stdout, stderr = self._captured_bytes(error, result)
            stdout_bytes = self._meta._bounded_bytes(len(stdout))
            stderr_bytes = self._meta._bounded_bytes(len(stderr))
        if failure_kind == "process_start_failed" and isinstance(error, ExecutionError):
            if error.cause in _PROCESS_START_CAUSES:
                process_start_cause = error.cause
        if failure_kind == "timeout":
            value = self._specification_value(specification, "timeout_seconds")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                timeout_seconds = self._meta._bounded_seconds(value)
        if failure_kind == "output_too_large_after_capture":
            value = self._specification_value(
                specification, "maximum_accepted_output_bytes"
            )
            if isinstance(value, int) and not isinstance(value, bool):
                maximum_accepted_output_bytes = self._meta._bounded_bytes(value)
        if failure_kind == "parsing_failed":
            output = self._specification_value(specification, "output")
            selected_parser = self._specification_value(output, "parser")
            if isinstance(selected_parser, str):
                selected_parser = selected_parser.lower()
                parser_name = (
                    selected_parser
                    if selected_parser in _PARSER_NAMES
                    else "unrecognized"
                )
            if isinstance(error, (OcsfDecodeError, OcsfMappingError)):
                ocsf_error_code = self._safe_ocsf_code(error)
                record_index = self._safe_record_index(error.record_index)
            if isinstance(error, OcsfMappingError):
                source_path = self._safe_ocsf_source_path(error.source_path)
        if failure_kind not in {"execution_failed", "unsuccessful_process"}:
            safe_return_code = None
        return _AssessmentFailure.from_evidence(
            stage="assessment_execution",
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            evidence=executable,
            return_code=safe_return_code,
            process_start_cause=process_start_cause,
            timeout_seconds=timeout_seconds,
            maximum_accepted_output_bytes=maximum_accepted_output_bytes,
            parser_name=parser_name,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            ocsf_error_code=ocsf_error_code,
            record_index=record_index,
            source_path=source_path,
        )

    def _executable_evidence(
        self, configured_executable: object, specification: object | None
    ) -> _ExecutableEvidence:
        """Extract path and stat evidence without trusting command internals."""
        configured_path: str | None = None
        actual_path: str | None = None
        try:
            configured_path = self._meta._safe_text(str(configured_executable))
        except Exception:
            configured_path = None
        actual = self._specification_value(specification, "executable")
        if isinstance(actual, str):
            actual_path = self._meta._safe_text(actual)
        elif configured_path is not None:
            actual_path = configured_path
        try:
            diagnostics = self._facade._executable_diagnostics(
                actual_path or configured_path or ""
            )
        except Exception:
            diagnostics = {
                "executable_is_absolute": False,
                "executable_exists": False,
                "executable_is_file": False,
                "executable_is_executable": False,
            }
        return _ExecutableEvidence(
            configured_executable_path=configured_path,
            actual_executable_path=actual_path,
            executable_is_absolute=bool(diagnostics["executable_is_absolute"]),
            executable_exists=bool(diagnostics["executable_exists"]),
            executable_is_file=bool(diagnostics["executable_is_file"]),
            executable_is_executable=bool(diagnostics["executable_is_executable"]),
        )

    @staticmethod
    def _specification_value(source: object, name: str) -> object | None:
        """Read one approved command-specification field without propagating."""
        try:
            value: object = getattr(source, name)
            return value
        except Exception:
            return None

    @staticmethod
    def _safe_ocsf_code(error: OcsfDecodeError | OcsfMappingError) -> str:
        """Normalize OCSF error codes through type-specific closed allowlists."""
        code = error.code
        allowed = (
            _OCSF_DECODE_CODES
            if isinstance(error, OcsfDecodeError)
            else _OCSF_MAPPING_CODES
        )
        return code if code in allowed else _OCSF_CODE_SENTINEL

    def _safe_record_index(self, value: object) -> int | None:
        """Keep only a bounded nonnegative OCSF record index."""
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return self._facade._bounded_count(value)

    @staticmethod
    def _safe_ocsf_source_path(value: object) -> str | None:
        """Admit only static or indexed paths generated by findings.py."""
        if value is None:
            return None
        if not isinstance(value, str):
            return _OCSF_SOURCE_PATH_SENTINEL
        if value in _OCSF_SOURCE_PATHS or _OCSF_INDEXED_SOURCE_PATH_PATTERN.fullmatch(
            value
        ):
            return value
        return _OCSF_SOURCE_PATH_SENTINEL

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

    def _classify_exception_failure(
        self,
        stage: str,
        error: Exception,
        *,
        configured_executable: object | None = None,
    ) -> _FailurePresentation:
        """Classify a raised failure without reading its text or representation."""
        if stage == "input_validation" and isinstance(error, ContractInputError):
            issues, omitted, truncated = self._safe_input_issues(error)
            return _InputValidationFailure(
                stage=stage,
                failure_kind="invalid_input",
                failure_summary=_SUMMARY_BY_FAILURE_KIND["invalid_input"],
                operator_guidance=self._input_guidance(
                    error, issues, truncated=truncated
                ),
                issues=tuple(issues),
                issues_omitted=omitted,
                issues_truncated=truncated,
            )
        if stage == "assessment_execution" and isinstance(
            error, (OcsfDecodeError, OcsfMappingError)
        ):
            executable = self._executable_evidence(configured_executable, None)
            return _OcsfDecodeFailure.from_evidence(
                stage=stage,
                failure_kind="parsing_failed",
                failure_summary=_SUMMARY_BY_FAILURE_KIND["parsing_failed"],
                operator_guidance=_GUIDANCE_BY_FAILURE_KIND["parsing_failed"],
                evidence=executable,
                ocsf_error_code=self._safe_ocsf_code(error),
                record_index=self._safe_record_index(error.record_index),
                source_path=(
                    self._safe_ocsf_source_path(error.source_path)
                    if isinstance(error, OcsfMappingError)
                    else None
                ),
            )
        if stage == "assessment_execution" and isinstance(
            error,
            (
                OutputArtifactError,
                OutputWorkspacePreparationError,
                OutputWorkspaceCleanupError,
            ),
        ):
            return self._classify_artifact_failure(error, configured_executable)
        executable = (
            self._executable_evidence(configured_executable, None)
            if stage in {"assessment_execution", "output_preparation"}
            else _ExecutableEvidence()
        )
        return _UnexpectedFailure.from_evidence(
            stage=stage,
            failure_kind="unexpected_failure",
            failure_summary=_SUMMARY_BY_FAILURE_KIND["unexpected_failure"],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND["unexpected_failure"],
            evidence=executable,
        )

    def _classify_artifact_failure(
        self,
        error: (
            OutputArtifactError
            | OutputWorkspacePreparationError
            | OutputWorkspaceCleanupError
        ),
        configured_executable: object | None,
    ) -> _FailurePresentation:
        """Classify typed artifact lifecycle errors without reading error text."""
        if isinstance(error, OutputArtifactError):
            failure_kind = _ARTIFACT_FAILURE_KIND.get(error.kind, "unexpected_failure")
            failure_stage = "artifact_capture"
        elif isinstance(error, OutputWorkspacePreparationError):
            failure_kind = "output_workspace_preparation_failed"
            failure_stage = "output_workspace_preparation"
        else:
            failure_kind = "output_workspace_cleanup_failed"
            failure_stage = "output_workspace_cleanup"

        result = getattr(error, "command_result", None)
        specification = getattr(result, "specification", None)
        executable = self._executable_evidence(configured_executable, specification)
        return_code: int | None = None
        stdout_bytes: int | None = None
        stderr_bytes: int | None = None
        result_return_code = getattr(result, "return_code", None)
        if isinstance(result_return_code, int) and not isinstance(
            result_return_code, bool
        ):
            return_code = self._meta._bounded_return_code(result_return_code)
            stdout = getattr(result, "stdout", b"")
            stderr = getattr(result, "stderr", b"")
            stdout_bytes = self._meta._bounded_bytes(
                len(stdout) if isinstance(stdout, bytes) else 0
            )
            stderr_bytes = self._meta._bounded_bytes(
                len(stderr) if isinstance(stderr, bytes) else 0
            )
        return _ArtifactFailure.from_evidence(
            stage=failure_stage,
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            evidence=executable,
            return_code=return_code,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )

    def _classify_internal_failure(
        self,
        *,
        stage: Literal["output_preparation", "callback", "reception"],
        failure_kind: Literal[
            "structured_output_failed",
            "structured_output_too_large",
            "rendering_failed",
            "callback_failed",
            "reception_failed",
        ],
        configured_executable: object | None = None,
        specification: object | None = None,
        structured_output_bytes: int | None = None,
    ) -> _FailurePresentation:
        """Classify one fixed injector-owned failure."""
        executable = (
            self._executable_evidence(configured_executable, specification)
            if stage == "output_preparation"
            else _ExecutableEvidence()
        )
        return _InternalFailure.from_evidence(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            evidence=executable,
            maximum_accepted_structured_output_bytes=(
                _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES
                if failure_kind == "structured_output_too_large"
                else None
            ),
            structured_output_bytes=(
                self._meta._bounded_bytes(structured_output_bytes)
                if structured_output_bytes is not None
                else None
            ),
        )

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

    def _safe_input_issues(
        self, error: ContractInputError
    ) -> tuple[list[dict[str, object]], int, bool]:
        """Bound and normalize validation structure before it reaches logging."""
        selected = error.issues[:_MAX_LOG_ISSUES]
        omitted = self._facade._bounded_count(len(error.issues) - len(selected))
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
