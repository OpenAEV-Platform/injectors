"""OpenAEV runtime boundary for the Prowler injector."""

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Literal
from urllib.parse import urlsplit

from pyoaev.helpers import OpenAEVInjectorHelper
from pyoaev.utils import AppLogger

from prowler._core.cli_engine import CliEngineError, ExecutionError, ParsingError
from prowler._core.prowler_client import (
    OutputArtifactError,
    OutputWorkspaceCleanupError,
    OutputWorkspacePreparationError,
)
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, ProwlerContracts
from prowler.contracts.base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
)
from prowler.models import ConfigLoader
from prowler.models.findings import OcsfDecodeError, OcsfMappingError
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
_MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES = 32 * 1024 * 1024
_INJECT_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_INVALID_INJECT_ID_DIGEST_LENGTH = 16
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
_OCSF_DECODE_CODES = frozenset(
    {
        "invalid_json",
        "invalid_payload_type",
        "invalid_top_level",
        "invalid_utf8",
        "non_object_record",
    }
)
_OCSF_MAPPING_CODES = frozenset(
    {"command_not_successful", "invalid_source_value", "missing_source_path"}
)
_OCSF_CODE_SENTINEL = "unrecognized"
_OCSF_SOURCE_PATH_SENTINEL = "unrecognized_source_path"
_OCSF_SOURCE_PATHS = frozenset(
    {
        "cloud",
        "cloud.account",
        "cloud.account.uid",
        "cloud.provider",
        "cloud.region",
        "compliance",
        "compliance.requirements",
        "finding",
        "finding.desc",
        "finding.remediation",
        "finding.remediation.desc",
        "finding.remediation.kb_articles",
        "finding.remediation.kb_articles[0]",
        "finding.remediation.references",
        "finding.remediation.references[0]",
        "finding.title",
        "finding.uid",
        "finding_info",
        "finding_info.desc",
        "finding_info.remediation",
        "finding_info.remediation.desc",
        "finding_info.remediation.kb_articles",
        "finding_info.remediation.kb_articles[0]",
        "finding_info.remediation.references",
        "finding_info.remediation.references[0]",
        "finding_info.title",
        "finding_info.uid",
        "finding_info|finding",
        "remediation",
        "remediation.desc",
        "remediation.references",
        "remediation.references[0]",
        "remediation|finding.remediation",
        "remediation|finding_info.remediation",
        "resources",
        "resources[0]",
        "resources[0].name",
        "resources[0].namespace",
        "resources[0].uid",
        "severity",
        "status",
        "status_code",
        "unmapped",
        "unmapped.compliance",
        "unmapped.provider",
        "unmapped.provider_uid",
    }
)
_OCSF_INDEXED_SOURCE_PATH_PATTERN = re.compile(
    r"(?:compliance\.requirements|unmapped\.compliance)(?:\[[0-9]{1,6}\])+$"
)
_ARTIFACT_FAILURE_KIND = {
    "missing": "output_artifact_missing",
    "nonregular": "output_artifact_nonregular",
    "unreadable": "output_artifact_unreadable",
    "oversized": "output_artifact_oversized",
}

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
    "output_artifact_missing": (
        "Verify Prowler writes the expected OCSF artifact and retry."
    ),
    "output_artifact_nonregular": (
        "Verify the Prowler OCSF output is a regular file and retry."
    ),
    "output_artifact_unreadable": (
        "Verify the Prowler OCSF artifact is readable and retry."
    ),
    "output_artifact_oversized": (
        "Reduce the assessment scope so the OCSF artifact stays within its limit."
    ),
    "output_workspace_preparation_failed": (
        "Verify temporary output storage is available and retry."
    ),
    "output_workspace_cleanup_failed": (
        "Review temporary output storage cleanup and retry the assessment."
    ),
    "invalid_input": _GENERIC_INPUT_GUIDANCE,
    "structured_output_failed": "Review structured output projection and retry.",
    "structured_output_too_large": (
        "Reduce the assessment scope so structured output stays within its limit."
    ),
    "rendering_failed": "Review injector trace rendering configuration and retry.",
    "reception_failed": "Check OpenAEV connectivity and retry assessment reception.",
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
    "output_artifact_missing": "The expected Prowler OCSF artifact was not created.",
    "output_artifact_nonregular": (
        "The Prowler OCSF artifact was not an accepted regular file."
    ),
    "output_artifact_unreadable": "The Prowler OCSF artifact could not be read.",
    "output_artifact_oversized": (
        "The Prowler OCSF artifact exceeded the accepted size limit."
    ),
    "output_workspace_preparation_failed": (
        "The temporary Prowler output workspace could not be prepared."
    ),
    "output_workspace_cleanup_failed": (
        "The temporary Prowler output workspace could not be cleaned."
    ),
    "invalid_input": "The assessment input was invalid.",
    "structured_output_failed": (
        "The OpenAEV structured output could not be serialized."
    ),
    "structured_output_too_large": (
        "The OpenAEV structured output exceeded the accepted size limit."
    ),
    "rendering_failed": "The OpenAEV execution trace could not be rendered.",
    "reception_failed": "The assessment reception could not be acknowledged.",
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
class _ExecutableEvidence:
    """No-throw executable path and stat evidence."""

    configured_executable_path: str | None = None
    actual_executable_path: str | None = None
    executable_is_absolute: bool | None = None
    executable_exists: bool | None = None
    executable_is_file: bool | None = None
    executable_is_executable: bool | None = None


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
    maximum_accepted_structured_output_bytes: int | None = None
    structured_output_bytes: int | None = None
    parser_name: str | None = None
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    ocsf_error_code: str | None = None
    record_index: int | None = None
    source_path: str | None = None
    issues: tuple[dict[str, object], ...] | None = None
    issues_omitted: int = 0
    issues_truncated: bool = False


class ProwlerInjector:
    """Register and execute the available Prowler assessment contracts."""

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
        metadata: dict[str, object] | None = None
        try:
            raw_executable = str(self.config.prowler.executable_path)
            executable = self._safe_text(raw_executable)
            metadata = {
                "injector_id": self._safe_text(str(self.config.injector.id)),
                "injector_name": self._safe_text(str(self.config.injector.name)),
                "registered_contract_count": self._bounded_count(len(self.registry)),
                "configured_executable_path": executable,
            }
            metadata.update(self._executable_diagnostics(raw_executable))
        except Exception:
            metadata = None
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
            self._best_effort_context_metadata(started, safe_inject_id, stage=stage),
        )
        try:
            self.helper.api.inject.execution_reception(
                inject_id=inject_id, data={"tracking_total_count": 1}
            )
        except Exception:
            failure = self._classify_internal_failure(
                stage="reception", failure_kind="reception_failed"
            )
            metadata = self._best_effort_failure_metadata(
                started, safe_inject_id, contract, provider, failure
            )
            if metadata is not None:
                self._log_error(_ASSESSMENT_FAILED, metadata)
            return

        stage = "reception_acknowledged"
        self._log(
            "debug",
            _RECEPTION_ACKNOWLEDGED,
            self._best_effort_context_metadata(started, safe_inject_id, stage=stage),
        )
        try:
            stage = "contract_resolution"
            contract_id = self._contract_id(injection)
            contract = self.registry.resolve(contract_id)
            self._log(
                "debug",
                _CONTRACT_RESOLVED,
                self._best_effort_context_metadata(
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
                self._best_effort_context_metadata(
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
                self._best_effort_context_metadata(
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
                    outcome, configured_executable=self._configured_executable()
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
                failure_metadata = self._best_effort_failure_metadata(
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
                    execution_output_structured = json.dumps(
                        contract.output_payload(outcome.findings),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    structured_output_bytes = len(
                        execution_output_structured.encode("utf-8")
                    )
                except Exception:
                    failure = self._classify_internal_failure(
                        stage="output_preparation",
                        failure_kind="structured_output_failed",
                        configured_executable=self._configured_executable(),
                        specification=outcome.command_result.specification,
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
                    failure_metadata = self._best_effort_failure_metadata(
                        started,
                        safe_inject_id,
                        contract,
                        provider,
                        failure,
                    )
                else:
                    if (
                        structured_output_bytes
                        > _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES
                    ):
                        failure = self._classify_internal_failure(
                            stage="output_preparation",
                            failure_kind="structured_output_too_large",
                            configured_executable=self._configured_executable(),
                            specification=outcome.command_result.specification,
                            structured_output_bytes=structured_output_bytes,
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
                        failure_metadata = self._best_effort_failure_metadata(
                            started,
                            safe_inject_id,
                            contract,
                            provider,
                            failure,
                        )
                    else:
                        try:
                            execution_message = contract.render_trace(
                                provider,
                                outcome.findings,
                                duration,
                                raw_record_count=outcome.raw_record_count,
                                raw_output_bytes=outcome.raw_output_bytes,
                                raw_preview=outcome.raw_preview,
                            )
                        except Exception:
                            failure = self._classify_internal_failure(
                                stage="output_preparation",
                                failure_kind="rendering_failed",
                                configured_executable=self._configured_executable(),
                                specification=outcome.command_result.specification,
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
                            failure_metadata = self._best_effort_failure_metadata(
                                started,
                                safe_inject_id,
                                contract,
                                provider,
                                failure,
                            )
                        else:
                            callback = {
                                "execution_message": execution_message,
                                "execution_output_structured": (
                                    execution_output_structured
                                ),
                                "execution_status": "SUCCESS",
                                "execution_duration": duration,
                                "execution_action": "complete",
                            }
                            success_metadata = self._best_effort_success_metadata(
                                started,
                                safe_inject_id,
                                contract,
                                provider,
                                outcome,
                            )
        except Exception as error:
            duration = int(monotonic() - started)
            failure = self._classify_exception_failure(
                stage,
                error,
                configured_executable=self._configured_executable(),
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
            failure_metadata = self._best_effort_failure_metadata(
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
            metadata = self._best_effort_failure_metadata(
                started,
                safe_inject_id,
                contract,
                provider,
                failure,
                attempted_status=callback["execution_status"],
            )
            if metadata is not None:
                self._log_error(_CALLBACK_FAILED, metadata)
            return
        self._log(
            "debug",
            _CALLBACK_COMPLETED,
            self._best_effort_callback_metadata(
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

    def _best_effort_context_metadata(
        self,
        started: float,
        inject_id: str,
        *,
        stage: str,
        contract: BaseProwlerContract | None = None,
        provider: ProviderInput | None = None,
    ) -> dict[str, object] | None:
        """Keep lifecycle metadata construction outside the assessment path."""
        try:
            return self._context_metadata(
                started,
                inject_id,
                stage=stage,
                contract=contract,
                provider=provider,
            )
        except Exception:
            return None

    def _best_effort_success_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract,
        provider: ProviderInput,
        outcome: ContractExecutionOutcome,
    ) -> dict[str, object] | None:
        """Drop unavailable success metadata instead of changing the result."""
        try:
            return self._success_metadata(
                started, inject_id, contract, provider, outcome
            )
        except Exception:
            return None

    def _best_effort_failure_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        failure: _FailurePresentation,
        *,
        attempted_status: object | None = None,
    ) -> dict[str, object] | None:
        """Keep a failure callback deliverable when diagnostics cannot be built."""
        try:
            return self._failure_metadata(
                started,
                inject_id,
                contract,
                provider,
                failure,
                attempted_status=attempted_status,
            )
        except Exception:
            return None

    def _best_effort_callback_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        status: object,
    ) -> dict[str, object] | None:
        """Keep delivered callbacks final even if completion metadata fails."""
        try:
            return self._callback_metadata(
                started, inject_id, contract, provider, status
            )
        except Exception:
            return None

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
            raw_record_count=cls._bounded_count(outcome.raw_record_count),
            raw_output_bytes=cls._bounded_bytes(outcome.raw_output_bytes),
            artifact_capture_phase="complete",
            ocsf_mapping_phase="complete",
        )
        return metadata

    @classmethod
    def _classify_assessment_failure(
        cls,
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
            cls._bounded_return_code(return_code)
            if isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and return_code != 0
            else None
        )
        executable = cls._executable_evidence(configured_executable, specification)
        configured_path = executable.configured_executable_path
        actual_path = executable.actual_executable_path
        executable_is_absolute = executable.executable_is_absolute
        executable_exists = executable.executable_exists
        executable_is_file = executable.executable_is_file
        executable_is_executable = executable.executable_is_executable
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
            stdout, stderr = cls._captured_bytes(error, result)
            stdout_bytes = cls._bounded_bytes(len(stdout))
            stderr_bytes = cls._bounded_bytes(len(stderr))
        if failure_kind == "process_start_failed" and isinstance(error, ExecutionError):
            if error.cause in _PROCESS_START_CAUSES:
                process_start_cause = error.cause
        if failure_kind == "timeout":
            value = cls._specification_value(specification, "timeout_seconds")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                timeout_seconds = cls._bounded_seconds(value)
        if failure_kind == "output_too_large_after_capture":
            value = cls._specification_value(
                specification, "maximum_accepted_output_bytes"
            )
            if isinstance(value, int) and not isinstance(value, bool):
                maximum_accepted_output_bytes = cls._bounded_bytes(value)
        if failure_kind == "parsing_failed":
            output = cls._specification_value(specification, "output")
            selected_parser = cls._specification_value(output, "parser")
            if isinstance(selected_parser, str):
                selected_parser = selected_parser.lower()
                parser_name = (
                    selected_parser
                    if selected_parser in _PARSER_NAMES
                    else "unrecognized"
                )
            if isinstance(error, (OcsfDecodeError, OcsfMappingError)):
                ocsf_error_code = cls._safe_ocsf_code(error)
                record_index = cls._safe_record_index(error.record_index)
            if isinstance(error, OcsfMappingError):
                source_path = cls._safe_ocsf_source_path(error.source_path)
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
            ocsf_error_code=ocsf_error_code,
            record_index=record_index,
            source_path=source_path,
        )

    @classmethod
    def _executable_evidence(
        cls, configured_executable: object, specification: object | None
    ) -> _ExecutableEvidence:
        """Extract path and stat evidence without trusting command internals."""
        configured_path: str | None = None
        actual_path: str | None = None
        try:
            configured_path = cls._safe_text(str(configured_executable))
        except Exception:
            configured_path = None
        actual = cls._specification_value(specification, "executable")
        if isinstance(actual, str):
            actual_path = cls._safe_text(actual)
        elif configured_path is not None:
            actual_path = configured_path
        try:
            diagnostics = cls._executable_diagnostics(
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

    def _configured_executable(self) -> object | None:
        """Read the configured executable only as optional diagnostic evidence."""
        try:
            executable: object = self.config.prowler.executable_path
            return executable
        except Exception:
            return None

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

    @classmethod
    def _safe_record_index(cls, value: object) -> int | None:
        """Keep only a bounded nonnegative OCSF record index."""
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return cls._bounded_count(value)

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

    @classmethod
    def _classify_exception_failure(
        cls,
        stage: str,
        error: Exception,
        *,
        configured_executable: object | None = None,
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
        if stage == "assessment_execution" and isinstance(
            error, (OcsfDecodeError, OcsfMappingError)
        ):
            executable = cls._executable_evidence(configured_executable, None)
            return _FailurePresentation(
                stage=stage,
                failure_kind="parsing_failed",
                failure_summary=_SUMMARY_BY_FAILURE_KIND["parsing_failed"],
                operator_guidance=_GUIDANCE_BY_FAILURE_KIND["parsing_failed"],
                configured_executable_path=executable.configured_executable_path,
                actual_executable_path=executable.actual_executable_path,
                executable_is_absolute=executable.executable_is_absolute,
                executable_exists=executable.executable_exists,
                executable_is_file=executable.executable_is_file,
                executable_is_executable=executable.executable_is_executable,
                ocsf_error_code=cls._safe_ocsf_code(error),
                record_index=cls._safe_record_index(error.record_index),
                source_path=(
                    cls._safe_ocsf_source_path(error.source_path)
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
            return cls._classify_artifact_failure(error, configured_executable)
        executable = (
            cls._executable_evidence(configured_executable, None)
            if stage in {"assessment_execution", "output_preparation"}
            else _ExecutableEvidence()
        )
        return _FailurePresentation(
            stage=stage,
            failure_kind="unexpected_failure",
            failure_summary=_SUMMARY_BY_FAILURE_KIND["unexpected_failure"],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND["unexpected_failure"],
            configured_executable_path=executable.configured_executable_path,
            actual_executable_path=executable.actual_executable_path,
            executable_is_absolute=executable.executable_is_absolute,
            executable_exists=executable.executable_exists,
            executable_is_file=executable.executable_is_file,
            executable_is_executable=executable.executable_is_executable,
        )

    @classmethod
    def _classify_artifact_failure(
        cls,
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
        executable = cls._executable_evidence(configured_executable, specification)
        return_code: int | None = None
        stdout_bytes: int | None = None
        stderr_bytes: int | None = None
        result_return_code = getattr(result, "return_code", None)
        if isinstance(result_return_code, int) and not isinstance(
            result_return_code, bool
        ):
            return_code = cls._bounded_return_code(result_return_code)
            stdout = getattr(result, "stdout", b"")
            stderr = getattr(result, "stderr", b"")
            stdout_bytes = cls._bounded_bytes(
                len(stdout) if isinstance(stdout, bytes) else 0
            )
            stderr_bytes = cls._bounded_bytes(
                len(stderr) if isinstance(stderr, bytes) else 0
            )
        return _FailurePresentation(
            stage=failure_stage,
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            return_code=return_code,
            configured_executable_path=executable.configured_executable_path,
            actual_executable_path=executable.actual_executable_path,
            executable_is_absolute=executable.executable_is_absolute,
            executable_exists=executable.executable_exists,
            executable_is_file=executable.executable_is_file,
            executable_is_executable=executable.executable_is_executable,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
        )

    @classmethod
    def _classify_internal_failure(
        cls,
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
            cls._executable_evidence(configured_executable, specification)
            if stage == "output_preparation"
            else _ExecutableEvidence()
        )
        return _FailurePresentation(
            stage=stage,
            failure_kind=failure_kind,
            failure_summary=_SUMMARY_BY_FAILURE_KIND[failure_kind],
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            configured_executable_path=executable.configured_executable_path,
            actual_executable_path=executable.actual_executable_path,
            executable_is_absolute=executable.executable_is_absolute,
            executable_exists=executable.executable_exists,
            executable_is_file=executable.executable_is_file,
            executable_is_executable=executable.executable_is_executable,
            maximum_accepted_structured_output_bytes=(
                _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES
                if failure_kind == "structured_output_too_large"
                else None
            ),
            structured_output_bytes=(
                cls._bounded_bytes(structured_output_bytes)
                if structured_output_bytes is not None
                else None
            ),
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
            failure_kind=failure.failure_kind,
            failure_summary=failure.failure_summary,
            operator_guidance=failure.operator_guidance,
        )
        if failure.stage == "callback":
            metadata["assessment_status"] = (
                "SUCCESS" if attempted_status == "SUCCESS" else "ERROR"
            )
            metadata["delivery_status"] = "ERROR"
        else:
            metadata["status"] = "ERROR"
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
            "maximum_accepted_structured_output_bytes",
            "structured_output_bytes",
            "parser_name",
            "stdout_bytes",
            "stderr_bytes",
            "ocsf_error_code",
            "record_index",
            "source_path",
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
            assessment_status="SUCCESS" if status == "SUCCESS" else "ERROR",
            delivery_status="SUCCESS",
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
            for key, attribute in (
                ("contract_id", "contract_id"),
                ("route", "route_name"),
                ("provider", "provider"),
            ):
                value = cls._safe_attribute_text(contract, attribute)
                if value is not None:
                    metadata[key] = value
        if provider is not None:
            try:
                provider_metadata = cls._provider_metadata(provider)
            except Exception:
                provider_metadata = {}
            metadata.update(provider_metadata)
        return metadata

    @classmethod
    def _safe_attribute_text(cls, source: object, attribute: str) -> str | None:
        """Read and bound one allowlisted context attribute without propagating."""
        try:
            value = getattr(source, attribute)
            return cls._safe_text(value) if isinstance(value, str) else None
        except Exception:
            return None

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
            account = cls._safe_attribute_text(provider, "aws_account_id")
            region = cls._safe_attribute_text(provider, "aws_region")
            endpoint = cls._safe_attribute_text(provider, "aws_endpoint_url")
            metadata: dict[str, object] = {}
            if account is not None:
                metadata["aws_account_id"] = account
            if region is not None:
                metadata["aws_region"] = region
            try:
                session_token_present: bool | None = (
                    provider.aws_session_token is not None
                )
            except Exception:
                session_token_present = None
            if session_token_present is not None:
                metadata["aws_session_token_present"] = session_token_present
            metadata["aws_endpoint_override_present"] = endpoint is not None
            origin = cls._endpoint_origin(endpoint)
            if origin is not None:
                metadata["aws_endpoint_origin"] = origin
            return metadata
        if isinstance(provider, AzureProviderInput):
            metadata = {
                "azure_tenant_id_present": True,
                "azure_client_id_present": True,
                "azure_client_secret_present": True,
            }
            subscription = cls._safe_attribute_text(provider, "azure_subscription_id")
            azure_provider = cls._safe_attribute_text(provider, "azure_provider")
            if subscription is not None:
                metadata["azure_subscription_id"] = subscription
            if azure_provider is not None:
                metadata["azure_provider"] = azure_provider
            return metadata
        if isinstance(provider, GcpProviderInput):
            metadata = {"gcp_credentials_present": True}
            project = cls._safe_attribute_text(provider, "gcp_project_id")
            if project is not None:
                metadata["gcp_project_id"] = project
            return metadata
        if isinstance(provider, KubernetesProviderInput):
            metadata = {"kubernetes_credentials_present": True}
            context = cls._safe_attribute_text(provider, "kubernetes_context")
            if context is not None:
                metadata["kubernetes_context"] = context
            return metadata
        return {}

    @classmethod
    def _endpoint_origin(cls, value: str | None) -> str | None:
        """Reduce a validated AWS endpoint override to scheme and authority."""
        if value is None:
            return None
        try:
            endpoint = urlsplit(value)
            host = endpoint.hostname
            if endpoint.scheme.lower() not in {"http", "https"} or host is None:
                return None
            normalized_host = host.lower()
            if ":" in normalized_host:
                normalized_host = f"[{normalized_host}]"
            authority = normalized_host
            if endpoint.port is not None:
                authority = f"{authority}:{endpoint.port}"
            return cls._safe_text(f"{endpoint.scheme.lower()}://{authority}")
        except Exception:
            return None

    @staticmethod
    def _safe_inject_id(value: str) -> str:
        """Allow only bounded log-safe correlation syntax."""
        if _INJECT_ID_PATTERN.fullmatch(value):
            return value
        digest = sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()
        return f"invalid:{digest[:_INVALID_INJECT_ID_DIGEST_LENGTH]}"

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
        try:
            path = Path(executable)
            is_absolute = path.is_absolute()
            exists = path.exists()
            is_file = path.is_file()
            is_executable = is_file and os.access(path, os.X_OK)
        except Exception:
            is_absolute = False
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
            for label, attribute in (
                ("Contract", "contract_id"),
                ("Route", "route_name"),
                ("Provider", "provider"),
            ):
                value = cls._safe_attribute_text(contract, attribute)
                if value is not None:
                    lines.append(f"{label}: {value}")
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
            (
                "maximum_accepted_structured_output_bytes",
                "Accepted structured output byte limit",
            ),
            ("structured_output_bytes", "Structured output bytes"),
            ("parser_name", "Parser"),
            ("stdout_bytes", "Captured stdout bytes"),
            ("stderr_bytes", "Captured stderr bytes"),
            ("return_code", "Return code"),
            ("ocsf_error_code", "OCSF error code"),
            ("record_index", "OCSF record index"),
            ("source_path", "OCSF source path"),
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
