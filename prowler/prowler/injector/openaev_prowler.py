"""OpenAEV runtime boundary for the Prowler injector."""

import json
from collections.abc import Mapping
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

_SAFE_EXECUTION_ERROR = "Prowler contract execution failed safely"
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
                callback = {
                    "execution_message": self._render_safe_error(
                        contract, provider, duration
                    ),
                    "execution_status": "ERROR",
                    "execution_duration": duration,
                    "execution_action": "complete",
                }
                failure_metadata = self._assessment_failure_metadata(
                    contract, outcome, duration
                )
            else:
                stage = "output_preparation"
                duration = int(monotonic() - started)
                try:
                    execution_message = contract.render_trace(
                        provider, outcome.findings, duration
                    )
                except Exception:
                    callback = {
                        "execution_message": _SAFE_EXECUTION_ERROR,
                        "execution_status": "ERROR",
                        "execution_duration": duration,
                        "execution_action": "complete",
                    }
                    failure_metadata = self._internal_failure_metadata(
                        contract,
                        stage="output_preparation",
                        failure_kind="rendering_failed",
                        duration=duration,
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
            callback = {
                "execution_message": self._render_safe_error(
                    contract, provider, duration
                ),
                "execution_status": "ERROR",
                "execution_duration": duration,
                "execution_action": "complete",
            }
            failure_metadata = self._exception_failure_metadata(
                contract, stage, error, duration
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
            self._log_error(
                _ASSESSMENT_FAILED,
                self._internal_failure_metadata(
                    contract,
                    stage="callback",
                    failure_kind="callback_failed",
                    duration=duration,
                ),
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
    def _assessment_failure_metadata(
        cls,
        contract: BaseProwlerContract,
        outcome: ContractExecutionOutcome,
        duration: int,
    ) -> dict[str, object]:
        """Classify one returned assessment failure through a closed allowlist."""
        error = outcome.error
        failure_kind = "unexpected_failure"
        if (
            isinstance(error, CliEngineError)
            and error.kind in _ALLOWED_CLI_FAILURE_KINDS
        ):
            failure_kind = error.kind
        metadata = cls._route_metadata(contract)
        metadata.update(
            status="ERROR",
            duration_seconds=cls._bounded_duration(duration),
            stage="assessment_execution",
            failure_kind=failure_kind,
        )
        return_code = error.return_code if isinstance(error, ExecutionError) else None
        if return_code is None:
            return_code = outcome.command_result.return_code
        if (
            isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and return_code
        ):
            metadata["return_code"] = return_code
        return metadata

    @classmethod
    def _exception_failure_metadata(
        cls,
        contract: BaseProwlerContract | None,
        stage: str,
        error: Exception,
        duration: int,
    ) -> dict[str, object]:
        """Collapse raised failures without reading their text or representation."""
        metadata = cls._route_metadata(contract) if contract is not None else {}
        metadata.update(
            status="ERROR",
            duration_seconds=cls._bounded_duration(duration),
            stage=stage,
            failure_kind="unexpected_failure",
        )
        if stage == "input_validation" and isinstance(error, ContractInputError):
            metadata["failure_kind"] = "invalid_input"
            issues, omitted, truncated = cls._safe_input_issues(error)
            metadata["issues"] = issues
            if omitted:
                metadata["issues_omitted"] = omitted
            if truncated:
                metadata["issues_truncated"] = True
        return metadata

    @classmethod
    def _internal_failure_metadata(
        cls,
        contract: BaseProwlerContract | None,
        *,
        stage: Literal["output_preparation", "callback"],
        failure_kind: Literal["rendering_failed", "callback_failed"],
        duration: int,
    ) -> dict[str, object]:
        """Describe one fixed injector-owned failure without exception data."""
        metadata = cls._route_metadata(contract) if contract is not None else {}
        metadata.update(
            status="ERROR",
            duration_seconds=cls._bounded_duration(duration),
            stage=stage,
            failure_kind=failure_kind,
        )
        return metadata

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
    def _render_safe_error(
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        duration: int,
    ) -> str:
        """Use a resolved contract's renderer without admitting exception details."""
        if contract is None:
            return _SAFE_EXECUTION_ERROR
        try:
            return contract.render_trace(
                provider,
                (),
                duration,
                is_error=True,
                error_message=_SAFE_EXECUTION_ERROR,
            )
        except Exception:
            return _SAFE_EXECUTION_ERROR

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
