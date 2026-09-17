"""Local deterministic CHK.014 fixtures."""

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
def provider_forms() -> dict[str, dict[str, object]]:
    """Return valid placeholder-only forms for all four providers."""
    return {
        "aws": {
            "aws_access_key_id": "CANARY-AWS-ACCESS",
            "aws_secret_access_key": "CANARY-AWS-SECRET",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
            "aws_session_token": "CANARY-AWS-SESSION",
        },
        "azure": {
            "azure_tenant_id": "CANARY-AZURE-TENANT",
            "azure_client_id": "CANARY-AZURE-CLIENT",
            "azure_client_secret": "CANARY-AZURE-SECRET",
            "azure_subscription_id": "subscription-123",
            "azure_provider": "Microsoft.Compute",
        },
        "gcp": {
            "gcp_service_account_json": "CANARY-GCP-SERVICE-ACCOUNT",
            "gcp_project_id": "acme-prod",
        },
        "kubernetes": {
            "kubernetes_kubeconfig": "CANARY-KUBECONFIG-CONTENT",
            "kubernetes_context": "acme-prod-cluster",
        },
    }


@pytest.fixture
def cis_ocsf_record_factory() -> Any:
    """Build a complete OCSF record with caller-controlled compliance values."""

    def build(
        title: str,
        *,
        provider: str = "aws",
        status: str = "FAIL",
        compliance: object = ("1.1", "1.1", "2.2"),
    ) -> dict[str, Any]:
        if status == "PASS":
            record_status, status_code = "New", "PASS"
        elif status == "MUTED":
            record_status, status_code = "Suppressed", "FAIL"
        else:
            record_status, status_code = "New", status
        resources = [{"uid": f"asset-{title}", "name": f"Asset {title}"}]
        unmapped = {"compliance": compliance}
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
            unmapped.update(provider=provider, provider_uid="acme-prod-cluster")
        else:
            record["cloud"] = {
                "provider": provider,
                "region": "eu-west-1",
                "account": {"uid": "account-123"},
            }
        return record

    return build
