"""Process-local client contracts for asynchronous Prowler assessments."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

from prowler.models.configs.config_loader import ProwlerConfig
from prowler.models.provider_inputs import ProviderInput

AssessmentState = Literal["queued", "running", "succeeded", "failed", "cancelled"]


class ProwlerClientError(Exception):
    """Structured error whose representation contains only safe context."""

    def __init__(self, code: str, message: str, details: Mapping[str, object]) -> None:
        self.code = code
        self.message = message
        self.details = dict(details)
        super().__init__(code, message, self.details)


@dataclass(frozen=True)
class AssessmentHandle:
    """Opaque identifier for one asynchronous assessment."""

    value: str


@dataclass(frozen=True)
class AssessmentRequest:
    """Values needed by a backend to begin an assessment."""

    provider: object
    executable_path: str
    check_filters: tuple[str, ...]


@dataclass(frozen=True)
class AssessmentStatus:
    """Current explicit state and optional structured failure."""

    state: AssessmentState
    error: ProwlerClientError | None = None


class AssessmentBackend(Protocol):
    """Port implemented by asynchronous assessment backends."""

    def start(self, handle: AssessmentHandle, request: AssessmentRequest) -> None:
        """Register a queued assessment."""

    def poll(self, handle: AssessmentHandle) -> AssessmentStatus:
        """Return the assessment's current state."""


class InMemoryAssessmentBackend:
    """Explicit process-local backend suitable for composition and tests."""

    def __init__(self) -> None:
        self._requests: dict[AssessmentHandle, AssessmentRequest] = {}
        self._statuses: dict[AssessmentHandle, AssessmentStatus] = {}

    def start(self, handle: AssessmentHandle, request: AssessmentRequest) -> None:
        """Store a newly queued request without automatic progression."""
        self._requests[handle] = request
        self._statuses[handle] = AssessmentStatus("queued")

    def poll(self, handle: AssessmentHandle) -> AssessmentStatus:
        """Return state or a safe unknown-handle error."""
        try:
            return self._statuses[handle]
        except KeyError as exc:
            raise ProwlerClientError(
                "unknown_assessment",
                "assessment handle is not known",
                {"handle_type": type(handle).__name__},
            ) from exc

    def request_for(self, handle: AssessmentHandle) -> AssessmentRequest:
        """Expose a stored request without changing assessment state."""
        return self._requests[handle]

    def set_state(
        self,
        handle: AssessmentHandle,
        state: AssessmentState,
        *,
        error: ProwlerClientError | None = None,
    ) -> None:
        """Set state explicitly for an existing assessment."""
        if handle not in self._statuses:
            self.poll(handle)
        self._statuses[handle] = AssessmentStatus(state, error)


def _invalid_output(reason: str, **details: object) -> ProwlerClientError:
    return ProwlerClientError(
        "invalid_ocsf_output",
        "Prowler output is not a non-empty sequence of object records",
        {"reason": reason, **details},
    )


def parse_ocsf_output(payload: str | bytes) -> list[dict[str, object]]:
    """Parse a JSON array or JSON Lines without exposing rejected payloads."""
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _invalid_output("invalid_encoding", format="utf-8") from exc
    else:
        text = payload

    if not text.strip():
        raise _invalid_output("empty_document")

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        try:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as exc:
            raise _invalid_output("malformed_json") from exc
    else:
        records = document if isinstance(document, list) else []

    if not records or not all(isinstance(record, dict) for record in records):
        raise _invalid_output("invalid_record_sequence")
    return records


class ProwlerClient:
    """Start, poll, and parse asynchronous Prowler assessments."""

    def __init__(
        self,
        *,
        provider: ProviderInput,
        config: ProwlerConfig,
        backend: AssessmentBackend,
    ) -> None:
        self._provider = provider
        self._backend = backend
        self.executable_path: Path = config.executable_path

    def start_scan(self, check_filters: Sequence[object]) -> AssessmentHandle:
        """Validate filters, preserve order, and queue an assessment."""
        if not check_filters or any(
            not isinstance(item, str) or not item.strip() for item in check_filters
        ):
            raise ProwlerClientError(
                "invalid_check_filters",
                "at least one non-blank string check filter is required",
                {"filter_count": len(check_filters)},
            )
        validated_filters = tuple(
            item for item in check_filters if isinstance(item, str)
        )
        handle = AssessmentHandle(f"assessment-{uuid4()}")
        request = AssessmentRequest(
            provider=self._provider,
            executable_path=str(self.executable_path),
            check_filters=validated_filters,
        )
        self._backend.start(handle, request)
        return handle

    def poll_scan(self, handle: object) -> AssessmentStatus:
        """Poll a well-formed opaque assessment handle."""
        if not isinstance(handle, AssessmentHandle) or not handle.value.strip():
            raise ProwlerClientError(
                "invalid_assessment_handle",
                "assessment handle is malformed",
                {"handle_type": type(handle).__name__},
            )
        return self._backend.poll(handle)

    @staticmethod
    def parse_ocsf_output(payload: str | bytes) -> list[dict[str, object]]:
        """Parse Prowler's OCSF records."""
        return parse_ocsf_output(payload)
