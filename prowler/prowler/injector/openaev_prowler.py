"""OpenAEV runtime boundary for the Prowler injector."""

import json
from collections.abc import Mapping
from time import monotonic

from pyoaev.helpers import OpenAEVInjectorHelper

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
        "resolution_failed",
        "execution_failed",
        "parsing_failed",
    }
)
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
        self.helper.injector_logger.info(_LISTENER_START)
        self.config.to_daemon_config(self.registry)
        self.helper.listen(message_callback=self.process_message)

    def process_message(self, data: dict[str, object]) -> None:
        """Receive, validate, dispatch once, and send one terminal callback."""
        started = monotonic()
        injection = data.get("injection")
        if not isinstance(injection, Mapping):
            self.helper.injector_logger.warning(_INVALID_MESSAGE)
            return
        inject_id = injection.get("inject_id")
        if not isinstance(inject_id, str) or not inject_id:
            self.helper.injector_logger.warning(_INVALID_MESSAGE)
            return
        self.helper.injector_logger.info(_ASSESSMENT_RECEIVED)
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
                raise ValueError("inject content is missing or invalid")
            provider = contract.parse_input(content)
            route_metadata = self._route_metadata(contract)
            self.helper.injector_logger.debug(_ASSESSMENT_VALIDATED, route_metadata)
            stage = "assessment_execution"
            self.helper.injector_logger.info(_EXECUTION_STARTED, route_metadata)
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
                callback = {
                    "execution_message": contract.render_trace(
                        provider, outcome.findings, duration
                    ),
                    "execution_output_structured": json.dumps(
                        contract.output_payload(outcome.findings),
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    "execution_status": "SUCCESS",
                    "execution_duration": duration,
                    "execution_action": "complete",
                }
                success_metadata = self._success_metadata(contract, outcome, duration)
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

        # AppLogger.error forces exc_info=1. Keep this call outside the except suite
        # so Python has cleared the active exception before the logger inspects it.
        if failure_metadata is not None:
            self.helper.injector_logger.error(_ASSESSMENT_FAILED, failure_metadata)
        elif success_metadata is not None:
            self.helper.injector_logger.info(_ASSESSMENT_SUCCEEDED, success_metadata)
        self.helper.api.inject.execution_callback(inject_id=inject_id, data=callback)
        self.helper.injector_logger.debug(
            _CALLBACK_COMPLETED,
            self._callback_metadata(contract, callback["execution_status"], duration),
        )

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
            metadata["issues"] = [
                {"location": list(issue.location), "type": issue.error_type}
                for issue in error.issues
            ]
        return metadata

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
        return contract.render_trace(
            provider,
            (),
            duration,
            is_error=True,
            error_message=_SAFE_EXECUTION_ERROR,
        )

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
