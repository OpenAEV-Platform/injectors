"""Build bounded lifecycle metadata and sanitized diagnostic values."""

from __future__ import annotations

import os
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING

from prowler.contracts.base import BaseProwlerContract, ContractExecutionOutcome
from prowler.injector.failure_taxonomy import (
    _CONTRACT_FIELDS,
    _FAILURE_FIELDS,
    _MAX_BYTE_COUNT,
    _MAX_ELAPSED_MS,
    _MAX_LOG_COUNT,
    _MAX_LOG_DURATION_SECONDS,
    _FailurePresentation,
    _safe_text,
)
from prowler.models.provider_inputs import ProviderInput

if TYPE_CHECKING:
    from prowler.injector.openaev_prowler import ProwlerInjector


class LifecycleMetadataBuilder:
    """Build the closed correlation and success/failure metadata records."""

    def __init__(self, facade: ProwlerInjector) -> None:
        """Attach the facade so frozen-name routes resolve at call time."""
        self._facade = facade

    def _success_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract,
        provider: ProviderInput,
        outcome: ContractExecutionOutcome,
    ) -> dict[str, object]:
        """Summarize a successful result without retaining finding content."""
        metadata = self._facade._context_metadata(
            started,
            inject_id,
            stage="assessment_completion",
            contract=contract,
            provider=provider,
        )
        metadata.update(
            status="SUCCESS",
            finding_count=self._facade._bounded_count(len(outcome.findings)),
            vulnerability_count=self._facade._bounded_count(
                sum(
                    finding.expectation_result == "FAILED"
                    for finding in outcome.findings
                )
            ),
            raw_record_count=self._facade._bounded_count(outcome.raw_record_count),
            raw_output_bytes=self._bounded_bytes(outcome.raw_output_bytes),
            artifact_capture_phase="complete",
            ocsf_mapping_phase="complete",
        )
        return metadata

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
        metadata = self._facade._context_metadata(
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
        for key, _label in _FAILURE_FIELDS:
            value = getattr(failure, key, None)
            if value is not None:
                metadata[key] = value
        issues = getattr(failure, "issues", None)
        if issues is not None:
            metadata["issues"] = list(issues)
        issues_omitted = getattr(failure, "issues_omitted", 0)
        if issues_omitted:
            metadata["issues_omitted"] = issues_omitted
        if getattr(failure, "issues_truncated", False):
            metadata["issues_truncated"] = True
        return metadata

    def _callback_metadata(
        self,
        started: float,
        inject_id: str,
        contract: BaseProwlerContract | None,
        provider: ProviderInput | None,
        status: object,
    ) -> dict[str, object]:
        """Describe callback completion with attempted terminal status and context."""
        metadata = self._facade._context_metadata(
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
        metadata: dict[str, object] = {
            "inject_id": inject_id,
            "stage": stage,
            "elapsed_ms": self._elapsed_ms(started),
        }
        if contract is not None:
            for key, _label, attribute in _CONTRACT_FIELDS:
                value = self._safe_attribute_text(contract, attribute)
                if value is not None:
                    metadata[key] = value
        if provider is not None:
            try:
                provider_metadata = self._facade._provider_metadata(provider)
            except Exception:
                provider_metadata = {}
            metadata.update(provider_metadata)
        return metadata

    def _safe_attribute_text(self, source: object, attribute: str) -> str | None:
        """Read and bound one allowlisted context attribute without propagating."""
        try:
            value = getattr(source, attribute)
            return self._safe_text(value) if isinstance(value, str) else None
        except Exception:
            return None

    def _provider_metadata(self, provider: ProviderInput) -> dict[str, object]:
        """Return approved provider facts without reading credential values."""
        return provider.safe_log_metadata()

    def _safe_text(self, value: str) -> str:
        """Bound explicitly approved operational text."""
        return _safe_text(value)

    def _executable_diagnostics(self, executable: str) -> dict[str, object]:
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

    def _elapsed_ms(self, started: float) -> int:
        """Clamp monotonic elapsed time to the lifecycle metadata domain."""
        return max(0, min(int((monotonic() - started) * 1000), _MAX_ELAPSED_MS))

    def _bounded_bytes(self, value: int) -> int:
        """Clamp evidence byte counts to a closed non-negative domain."""
        return max(0, min(value, _MAX_BYTE_COUNT))

    def _bounded_return_code(self, value: int) -> int:
        """Clamp process return-code evidence to a small signed domain."""
        return max(-65_535, min(value, 65_535))

    def _bounded_seconds(self, value: float) -> float:
        """Clamp configured timeout evidence without inventing precision."""
        return max(0.0, min(float(value), float(_MAX_LOG_DURATION_SECONDS)))

    def _bounded_count(self, value: int) -> int:
        """Clamp count metadata to a small non-negative numeric domain."""
        return max(0, min(value, _MAX_LOG_COUNT))
