"""Render the closed failure presentation for OpenAEV callback messages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from prowler.contracts.base import BaseProwlerContract
from prowler.injector.failure_taxonomy import (
    _CONTRACT_FIELDS,
    _FAILURE_FIELDS,
    _FailurePresentation,
)

if TYPE_CHECKING:
    from prowler.injector.lifecycle_metadata import LifecycleMetadataBuilder
    from prowler.injector.openaev_prowler import ProwlerInjector


class FailurePresenter:
    """Render bounded failure diagnostics for the terminal callback message."""

    def __init__(self, facade: ProwlerInjector, meta: LifecycleMetadataBuilder) -> None:
        """Attach the facade and metadata builder for shared routing."""
        self._facade = facade
        self._meta = meta

    def _plain_safe_error(
        self,
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
            for _key, label, attribute in _CONTRACT_FIELDS:
                value = self._meta._safe_attribute_text(contract, attribute)
                if value is not None:
                    lines.append(f"{label}: {value}")
        for key, label in _FAILURE_FIELDS:
            value = getattr(failure, key, None)
            if value is not None:
                rendered = str(value).lower() if isinstance(value, bool) else str(value)
                lines.append(f"{label}: {rendered}")
        issues = getattr(failure, "issues", None)
        if issues is not None:
            for index, issue in enumerate(issues, 1):
                location = issue.get("location")
                error_type = issue.get("type")
                if isinstance(location, list) and isinstance(error_type, str):
                    field = ".".join(part for part in location if isinstance(part, str))
                    lines.append(f"Issue {index}: {field or 'input'} ({error_type})")
        issues_omitted = getattr(failure, "issues_omitted", 0)
        if issues_omitted:
            lines.append(f"Issues omitted: {issues_omitted}")
        if getattr(failure, "issues_truncated", False):
            lines.append("Issues truncated: true")
        return "\n".join(lines)

    def _render_safe_error(
        self,
        contract: BaseProwlerContract | None,
        duration: int,
        failure: _FailurePresentation,
        *,
        inject_id: str,
    ) -> str:
        """Render once, falling back to the same closed code and guidance."""
        safe_error = self._plain_safe_error(
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
