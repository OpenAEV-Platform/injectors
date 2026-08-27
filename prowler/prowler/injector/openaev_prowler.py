"""OpenAEV runtime boundary for the Prowler injector."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Literal

from pyoaev.helpers import OpenAEVInjectorHelper
from pyoaev.utils import AppLogger

from prowler._core.cli_engine import CliEngineError, ExecutionError
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
_ASSESSMENT_VALIDATED = "[PROWLER_INJECTOR] - Assessment validated"
_EXECUTION_STARTED = "[PROWLER_INJECTOR] - Assessment execution started"
_ASSESSMENT_SUCCEEDED = "[PROWLER_INJECTOR] - Assessment completed"
_ASSESSMENT_FAILED = "[PROWLER_INJECTOR] - Assessment failed safely"
_CALLBACK_COMPLETED = "[PROWLER_INJECTOR] - Assessment callback completed"

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
    "timeout": "Increase the configured timeout or reduce the assessment scope.",
    "process_start_failed": (
        "Verify the Prowler process can start with the configured executable."
    ),
    "unsuccessful_process": (
        "Review the Prowler configuration and retry the assessment."
    ),
    "output_too_large_after_capture": (
        "Reduce the assessment scope or increase the configured output limit."
    ),
    "parsing_failed": "Verify Prowler emits valid JSON-OCSF output and retry.",
    "invalid_input": _GENERIC_INPUT_GUIDANCE,
    "rendering_failed": "Review injector trace rendering configuration and retry.",
    "callback_failed": "Check OpenAEV connectivity and retry callback delivery.",
    "unexpected_failure": "Review injector configuration and retry the assessment.",
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
    operator_guidance: str
    return_code: int | None = None
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
        self._log("info", _LISTENER_START)
        self.config.to_daemon_config(self.registry)
        self.helper.listen(message_callback=self.process_message)

    def process_message(self, data: dict[str, object]) -> None:
        """Receive, validate, dispatch once, and send one terminal callback."""
        started = monotonic()
        injection = data.get("injection")
        if not isinstance(injection, Mapping):
            self._log("warning", _INVALID_MESSAGE)
            return
        inject_id = injection.get("inject_id")
        if not isinstance(inject_id, str) or not inject_id:
            self._log("warning", _INVALID_MESSAGE)
            return
        self._log("info", _ASSESSMENT_RECEIVED)
        self.helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        contract: BaseProwlerContract | None = None
        provider: ProviderInput | None = None
        failure_metadata: dict[str, object] | None = None
        success_metadata: dict[str, object] | None = None
        stage = "contract_resolution"
        try:
            contract_id = self._contract_id(injection)
            contract = self.registry.resolve(contract_id)
            stage = "input_validation"
            content = injection.get("inject_content")
            if not isinstance(content, Mapping):
                raise ContractInputError(())
            provider = contract.parse_input(content)
            route_metadata = self._route_metadata(contract)
            self._log("debug", _ASSESSMENT_VALIDATED, route_metadata)
            stage = "assessment_execution"
            self._log("info", _EXECUTION_STARTED, route_metadata)
            outcome = contract.execute(self.config.prowler, provider)
            if outcome.error is not None or outcome.command_result.return_code != 0:
                duration = int(monotonic() - started)
                failure = self._classify_assessment_failure(outcome)
                callback = {
                    "execution_message": self._render_safe_error(
                        contract, duration, failure
                    ),
                    "execution_status": "ERROR",
                    "execution_duration": duration,
                    "execution_action": "complete",
                }
                failure_metadata = self._failure_metadata(contract, failure, duration)
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
                        "execution_message": self._plain_safe_error(failure),
                        "execution_status": "ERROR",
                        "execution_duration": duration,
                        "execution_action": "complete",
                    }
                    failure_metadata = self._failure_metadata(
                        contract, failure, duration
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
                        contract, outcome, duration
                    )
        except Exception as error:
            duration = int(monotonic() - started)
            failure = self._classify_exception_failure(stage, error)
            callback = {
                "execution_message": self._render_safe_error(
                    contract, duration, failure
                ),
                "execution_status": "ERROR",
                "execution_duration": duration,
                "execution_action": "complete",
            }
            failure_metadata = self._failure_metadata(contract, failure, duration)

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
                _ASSESSMENT_FAILED,
                self._failure_metadata(contract, failure, duration),
            )
            return
        self._log(
            "debug",
            _CALLBACK_COMPLETED,
            self._callback_metadata(contract, callback["execution_status"], duration),
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

    @staticmethod
    def _route_metadata(contract: BaseProwlerContract) -> dict[str, object]:
        """Return only canonical registry-owned route identity."""
        return {"route": contract.route_name, "provider": contract.provider}

    @classmethod
    def _success_metadata(
        cls,
        contract: BaseProwlerContract,
        outcome: ContractExecutionOutcome,
        duration: int,
    ) -> dict[str, object]:
        """Summarize a successful result without retaining finding content."""
        metadata = cls._route_metadata(contract)
        metadata.update(
            status="SUCCESS",
            duration_seconds=cls._bounded_duration(duration),
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
        cls, outcome: ContractExecutionOutcome
    ) -> _FailurePresentation:
        """Classify one returned assessment failure exactly once."""
        error = outcome.error
        failure_kind = "unexpected_failure"
        if (
            isinstance(error, CliEngineError)
            and error.kind in _ALLOWED_CLI_FAILURE_KINDS
        ):
            failure_kind = error.kind
        return_code = error.return_code if isinstance(error, ExecutionError) else None
        if return_code is None:
            return_code = outcome.command_result.return_code
        safe_return_code = (
            return_code
            if isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and return_code != 0
            else None
        )
        return _FailurePresentation(
            stage="assessment_execution",
            failure_kind=failure_kind,
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
            return_code=safe_return_code,
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
            operator_guidance=_GUIDANCE_BY_FAILURE_KIND[failure_kind],
        )

    @classmethod
    def _failure_metadata(
        cls,
        contract: BaseProwlerContract | None,
        failure: _FailurePresentation,
        duration: int,
    ) -> dict[str, object]:
        """Project one closed failure presentation into safe log metadata."""
        metadata = cls._route_metadata(contract) if contract is not None else {}
        metadata.update(
            status="ERROR",
            duration_seconds=cls._bounded_duration(duration),
            stage=failure.stage,
            failure_kind=failure.failure_kind,
            operator_guidance=failure.operator_guidance,
        )
        if failure.return_code is not None:
            metadata["return_code"] = failure.return_code
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
        contract: BaseProwlerContract | None,
        status: object,
        duration: int,
    ) -> dict[str, object]:
        """Describe callback completion with route identity and fixed status only."""
        metadata = cls._route_metadata(contract) if contract is not None else {}
        metadata.update(
            status="SUCCESS" if status == "SUCCESS" else "ERROR",
            duration_seconds=cls._bounded_duration(duration),
        )
        return metadata

    @staticmethod
    def _bounded_count(value: int) -> int:
        """Clamp count metadata to a small non-negative numeric domain."""
        return max(0, min(value, _MAX_LOG_COUNT))

    @staticmethod
    def _bounded_duration(value: int) -> int:
        """Clamp duration metadata without changing callback duration behavior."""
        return max(0, min(value, _MAX_LOG_DURATION_SECONDS))

    @staticmethod
    def _plain_safe_error(failure: _FailurePresentation) -> str:
        """Render the bounded code and exact shared guidance without Rich."""
        return f"Error code: {failure.failure_kind}\n" f"{failure.operator_guidance}"

    @classmethod
    def _render_safe_error(
        cls,
        contract: BaseProwlerContract | None,
        duration: int,
        failure: _FailurePresentation,
    ) -> str:
        """Render once, falling back to the same closed code and guidance."""
        safe_error = cls._plain_safe_error(failure)
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
