"""OpenAEV runtime boundary for the Prowler injector."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from time import monotonic
from typing import Literal

from pyoaev.helpers import OpenAEVInjectorHelper
from pyoaev.utils import AppLogger

from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, ProwlerContracts
from prowler.contracts.base import (
    BaseProwlerContract,
    ContractExecutionOutcome,
    ContractInputError,
)
from prowler.injector.failure_classifier import FailureClassifier
from prowler.injector.failure_presentation import FailurePresenter
from prowler.injector.failure_taxonomy import (
    _ASSESSMENT_FAILED,
    _ASSESSMENT_RECEIVED,
    _ASSESSMENT_SUCCEEDED,
    _ASSESSMENT_VALIDATED,
    _CALLBACK_COMPLETED,
    _CALLBACK_FAILED,
    _CONTRACT_RESOLVED,
    _EXECUTION_STARTED,
    _INJECT_ID_PATTERN,
    _INVALID_INJECT_ID_DIGEST_LENGTH,
    _INVALID_MESSAGE,
    _LISTENER_START,
    _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES,
    _RECEPTION_ACKNOWLEDGED,
    _FailurePresentation,
    _terminal_callback,
)
from prowler.injector.lifecycle_metadata import LifecycleMetadataBuilder
from prowler.models import ConfigLoader
from prowler.models.provider_inputs import ProviderInput


class _Stage(Enum):
    """Closed assessment-pipeline stage values carried by ``_MessageRun``."""

    MESSAGE_RECEPTION = "message_reception"
    RECEPTION_ACKNOWLEDGED = "reception_acknowledged"
    CONTRACT_RESOLUTION = "contract_resolution"
    INPUT_VALIDATION = "input_validation"
    ASSESSMENT_EXECUTION = "assessment_execution"
    OUTPUT_PREPARATION = "output_preparation"


@dataclass
class _MessageRun:
    """One in-flight assessment message shared by the pipeline stage helpers."""

    started: float
    inject_id: str
    safe_inject_id: str
    stage: _Stage = _Stage.MESSAGE_RECEPTION
    contract: BaseProwlerContract | None = None
    provider: ProviderInput | None = None
    failure_metadata: dict[str, object] | None = None
    success_metadata: dict[str, object] | None = None


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
        self._meta = LifecycleMetadataBuilder(self)
        self._classifier = FailureClassifier(self, self._meta)
        self._presenter = FailurePresenter(self, self._meta)

    def start(self) -> None:
        """Start the injector listener after zero-contract registration."""
        metadata: dict[str, object] | None = None
        try:
            raw_executable = str(self.config.prowler.executable_path)
            executable = self._meta._safe_text(raw_executable)
            metadata = {
                "injector_id": self._meta._safe_text(str(self.config.injector.id)),
                "injector_name": self._meta._safe_text(str(self.config.injector.name)),
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
        run = _MessageRun(
            started=started,
            inject_id=inject_id,
            safe_inject_id=self._safe_inject_id(inject_id),
        )
        self._log(
            "info",
            _ASSESSMENT_RECEIVED,
            self._guard(
                lambda: self._context_metadata(
                    run.started, run.safe_inject_id, stage=run.stage.value
                )
            ),
        )
        if not self._ack_reception(run):
            return
        try:
            contract = self._resolve_contract(run, injection)
            provider = self._validate_input(run, injection, contract)
            run.stage = _Stage.ASSESSMENT_EXECUTION
            self._log(
                "info",
                _EXECUTION_STARTED,
                self._guard(
                    lambda: self._context_metadata(
                        run.started,
                        run.safe_inject_id,
                        stage=run.stage.value,
                        contract=contract,
                        provider=provider,
                    )
                ),
            )
            outcome = contract.execute(self.config.prowler, provider)
            if outcome.error is not None or outcome.command_result.return_code != 0:
                duration = int(monotonic() - started)
                failure = self._classifier._classify_assessment_failure(
                    outcome, configured_executable=self._configured_executable()
                )
                callback = _terminal_callback(
                    "ERROR",
                    self._presenter._render_safe_error(
                        contract,
                        duration,
                        failure,
                        inject_id=run.safe_inject_id,
                    ),
                    duration,
                )
                run.failure_metadata = self._guard(
                    lambda: self._failure_metadata(
                        run.started,
                        run.safe_inject_id,
                        run.contract,
                        run.provider,
                        failure,
                    )
                )
            else:
                callback = self._prepare_output(run, contract, provider, outcome)
        except Exception as error:
            duration = int(monotonic() - started)
            failure = self._classifier._classify_exception_failure(
                run.stage.value,
                error,
                configured_executable=self._configured_executable(),
            )
            callback = _terminal_callback(
                "ERROR",
                self._presenter._render_safe_error(
                    run.contract,
                    duration,
                    failure,
                    inject_id=run.safe_inject_id,
                ),
                duration,
            )
            run.failure_metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started,
                    run.safe_inject_id,
                    run.contract,
                    run.provider,
                    failure,
                )
            )
        if run.failure_metadata is not None:
            self._log_error(_ASSESSMENT_FAILED, run.failure_metadata)
        elif run.success_metadata is not None:
            self._log("info", _ASSESSMENT_SUCCEEDED, run.success_metadata)
        self._deliver_callback(run, callback)

    def _ack_reception(self, run: _MessageRun) -> bool:
        """Acknowledge reception and log the acknowledgment; stop on failure."""
        try:
            self.helper.api.inject.execution_reception(
                inject_id=run.inject_id, data={"tracking_total_count": 1}
            )
        except Exception:
            failure = self._classifier._classify_internal_failure(
                stage="reception", failure_kind="reception_failed"
            )
            metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started,
                    run.safe_inject_id,
                    run.contract,
                    run.provider,
                    failure,
                )
            )
            if metadata is not None:
                self._log_error(_ASSESSMENT_FAILED, metadata)
            return False
        run.stage = _Stage.RECEPTION_ACKNOWLEDGED
        self._log(
            "debug",
            _RECEPTION_ACKNOWLEDGED,
            self._guard(
                lambda: self._context_metadata(
                    run.started, run.safe_inject_id, stage=run.stage.value
                )
            ),
        )
        return True

    def _resolve_contract(
        self, run: _MessageRun, injection: Mapping[str, object]
    ) -> BaseProwlerContract:
        """Resolve the injected contract and log its correlation context."""
        run.stage = _Stage.CONTRACT_RESOLUTION
        contract_id = self._contract_id(injection)
        contract = self.registry.resolve(contract_id)
        run.contract = contract
        self._log(
            "debug",
            _CONTRACT_RESOLVED,
            self._guard(
                lambda: self._context_metadata(
                    run.started,
                    run.safe_inject_id,
                    stage=run.stage.value,
                    contract=contract,
                )
            ),
        )
        return contract

    def _validate_input(
        self,
        run: _MessageRun,
        injection: Mapping[str, object],
        contract: BaseProwlerContract,
    ) -> ProviderInput:
        """Strictly parse the injection content into a provider input."""
        run.stage = _Stage.INPUT_VALIDATION
        content = injection.get("inject_content")
        if not isinstance(content, Mapping):
            raise ContractInputError(())
        provider = contract.parse_input(content)
        run.provider = provider
        self._log(
            "debug",
            _ASSESSMENT_VALIDATED,
            self._guard(
                lambda: self._context_metadata(
                    run.started,
                    run.safe_inject_id,
                    stage=run.stage.value,
                    contract=contract,
                    provider=provider,
                )
            ),
        )
        return provider

    def _prepare_output(
        self,
        run: _MessageRun,
        contract: BaseProwlerContract,
        provider: ProviderInput,
        outcome: ContractExecutionOutcome,
    ) -> dict[str, object]:
        """Serialize, size-gate, and render the assessment output once."""
        run.stage = _Stage.OUTPUT_PREPARATION
        duration = int(monotonic() - run.started)
        try:
            execution_output_structured = json.dumps(
                contract.output_payload(outcome.findings),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            structured_output_bytes = len(execution_output_structured.encode("utf-8"))
        except Exception:
            failure = self._classifier._classify_internal_failure(
                stage="output_preparation",
                failure_kind="structured_output_failed",
                configured_executable=self._configured_executable(),
                specification=outcome.command_result.specification,
            )
            callback = _terminal_callback(
                "ERROR",
                self._presenter._plain_safe_error(
                    failure,
                    inject_id=run.safe_inject_id,
                    contract=contract,
                ),
                duration,
            )
            run.failure_metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started, run.safe_inject_id, contract, provider, failure
                )
            )
            return callback
        if structured_output_bytes > _MAXIMUM_ACCEPTED_STRUCTURED_OUTPUT_BYTES:
            failure = self._classifier._classify_internal_failure(
                stage="output_preparation",
                failure_kind="structured_output_too_large",
                configured_executable=self._configured_executable(),
                specification=outcome.command_result.specification,
                structured_output_bytes=structured_output_bytes,
            )
            callback = _terminal_callback(
                "ERROR",
                self._presenter._plain_safe_error(
                    failure,
                    inject_id=run.safe_inject_id,
                    contract=contract,
                ),
                duration,
            )
            run.failure_metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started, run.safe_inject_id, contract, provider, failure
                )
            )
            return callback
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
            failure = self._classifier._classify_internal_failure(
                stage="output_preparation",
                failure_kind="rendering_failed",
                configured_executable=self._configured_executable(),
                specification=outcome.command_result.specification,
            )
            callback = _terminal_callback(
                "ERROR",
                self._presenter._plain_safe_error(
                    failure,
                    inject_id=run.safe_inject_id,
                    contract=contract,
                ),
                duration,
            )
            run.failure_metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started, run.safe_inject_id, contract, provider, failure
                )
            )
            return callback
        callback = _terminal_callback(
            "SUCCESS",
            execution_message,
            duration,
            output_structured=execution_output_structured,
        )
        run.success_metadata = self._guard(
            lambda: self._success_metadata(
                run.started, run.safe_inject_id, contract, provider, outcome
            )
        )
        return callback

    def _deliver_callback(self, run: _MessageRun, callback: dict[str, object]) -> None:
        """Send the terminal callback and log completion or delivery failure."""
        try:
            self.helper.api.inject.execution_callback(
                inject_id=run.inject_id, data=callback
            )
        except Exception:
            failure = self._classifier._classify_internal_failure(
                stage="callback", failure_kind="callback_failed"
            )
            metadata = self._guard(
                lambda: self._failure_metadata(
                    run.started,
                    run.safe_inject_id,
                    run.contract,
                    run.provider,
                    failure,
                    attempted_status=callback["execution_status"],
                )
            )
            if metadata is not None:
                self._log_error(_CALLBACK_FAILED, metadata)
            return
        self._log(
            "debug",
            _CALLBACK_COMPLETED,
            self._guard(
                lambda: self._callback_metadata(
                    run.started,
                    run.safe_inject_id,
                    run.contract,
                    run.provider,
                    callback["execution_status"],
                )
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

    def _guard(self, fn: Callable[[], dict[str, object]]) -> dict[str, object] | None:
        """Return the diagnostics call result, or None when it cannot be built."""
        try:
            return fn()
        except Exception:
            return None

    def _success_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract,
        provider: ProviderInput,
        outcome: ContractExecutionOutcome,
    ) -> dict[str, object]:
        """Summarize a successful result without retaining finding content."""
        return self._meta._success_metadata(
            started, inject_id, contract, provider, outcome
        )

    def _failure_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        failure: _FailurePresentation,
        *,
        attempted_status: object | None = None,
    ) -> dict[str, object]:
        """Project one closed failure presentation into safe log metadata."""
        return self._meta._failure_metadata(
            started,
            inject_id,
            contract,
            provider,
            failure,
            attempted_status=attempted_status,
        )

    def _callback_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        status: object,
    ) -> dict[str, object]:
        """Describe callback completion with attempted terminal status and context."""
        return self._meta._callback_metadata(
            started, inject_id, contract, provider, status
        )

    def _context_metadata(
        self,
        started: float,
        inject_id: str,
        *,
        stage: str,
        contract: BaseProwlerContract | None = None,
        provider: ProviderInput | None = None,
    ) -> dict[str, object]:
        """Build the common bounded lifecycle correlation envelope."""
        return self._meta._context_metadata(
            started,
            inject_id,
            stage=stage,
            contract=contract,
            provider=provider,
        )

    def _provider_metadata(self, provider: ProviderInput) -> dict[str, object]:
        """Return approved provider facts without reading credential values."""
        return self._meta._provider_metadata(provider)

    def _executable_diagnostics(self, executable: str) -> dict[str, object]:
        """Inspect one approved executable path without raising into execution."""
        return self._meta._executable_diagnostics(executable)

    def _bounded_count(self, value: int) -> int:
        """Clamp count metadata to a small non-negative numeric domain."""
        return self._meta._bounded_count(value)

    def _configured_executable(self) -> object | None:
        """Read the configured executable only as optional diagnostic evidence."""
        try:
            executable: object = self.config.prowler.executable_path
            return executable
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
