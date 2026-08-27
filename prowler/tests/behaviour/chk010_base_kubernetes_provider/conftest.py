"""Local deterministic CHK.010 fixtures."""

from dataclasses import dataclass, field
from typing import Any

import pytest


@dataclass(frozen=True)
class RecordedLog:
    """One AppLogger-compatible call captured without formatting side effects."""

    level: str
    message: str
    metadata: dict[str, object] | None = None
    exc_info: bool | None = None


class _RecordingLocalLogger:
    """Capture the direct standard-library ERROR path used by the injector."""

    def __init__(self, events: list[RecordedLog]) -> None:
        self._events = events

    def error(
        self,
        message: str,
        *,
        exc_info: bool,
        extra: dict[str, object],
    ) -> None:
        """Record safe ERROR metadata in the same shape accepted by AppLogger."""
        attributes = extra.get("attributes")
        metadata = dict(attributes) if isinstance(attributes, dict) else None
        self._events.append(RecordedLog("error", message, metadata, exc_info))


@dataclass
class RecordingLogger:
    """Record the lifecycle logger surface exposed by the OpenAEV helper."""

    events: list[RecordedLog] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Attach the direct ERROR surface to the shared event stream."""
        self.local_logger = _RecordingLocalLogger(self.events)

    def debug(self, message: str, metadata: dict[str, object]) -> None:
        """Record one DEBUG lifecycle event."""
        self.events.append(RecordedLog("debug", message, metadata))

    def info(self, message: str, metadata: dict[str, object] | None = None) -> None:
        """Record one INFO lifecycle event."""
        self.events.append(RecordedLog("info", message, metadata))

    def warning(self, message: str) -> None:
        """Record one WARNING lifecycle event."""
        self.events.append(RecordedLog("warning", message))


@pytest.fixture
def kubernetes_form() -> dict[str, object]:
    """Return structurally valid placeholder-only Kubernetes form input."""
    return {
        "kubernetes_kubeconfig": "KUBECONFIG-CANARY\nFORM-CANARY",
        "kubernetes_context": "CONTEXT-CANARY",
    }


@pytest.fixture
def kubernetes_ocsf_record_factory() -> Any:
    """Build one complete minimal OCSF record for projection tests."""

    def build(
        title: str,
        *,
        provider: str = "kubernetes",
        status: str = "FAIL",
    ) -> dict[str, Any]:
        if status == "PASS":
            record_status, status_code = "New", "PASS"
        elif status == "MUTED":
            record_status, status_code = "Suppressed", "FAIL"
        else:
            record_status, status_code = "New", status
        resources = [{"uid": f"asset-{title}", "name": f"Asset {title}"}]
        unmapped = {"compliance": ["cis", "nis2"]}
        record = {
            "finding_info": {
                "uid": f"check-{title}",
                "title": title,
                "desc": f"Description {title}",
            },
            "status": record_status,
            "status_code": status_code,
            "severity": "High",
            "resources": resources,
            "unmapped": unmapped,
            "remediation": {
                "desc": f"Remediate {title}",
                "references": ["https://example.invalid/remediation"],
            },
        }
        if provider.casefold() == "kubernetes":
            resources[0]["namespace"] = "default"
            unmapped.update(provider=provider, provider_uid="CONTEXT-CANARY")
        else:
            record["cloud"] = {
                "provider": provider,
                "region": "cluster-local",
                "account": {"uid": "CONTEXT-CANARY"},
            }
        return record

    return build
