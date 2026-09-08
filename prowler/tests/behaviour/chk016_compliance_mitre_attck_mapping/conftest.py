"""Local deterministic CHK.016 fixtures."""

from typing import Any

import pytest


@pytest.fixture
def provider_forms() -> dict[str, dict[str, object]]:
    """Return valid placeholder-only forms for the three MITRE providers."""
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
    }


@pytest.fixture
def mitre_ocsf_record_factory() -> Any:
    """Build complete OCSF records with caller-controlled compliance values."""

    def build(
        title: str,
        *,
        provider: str = "aws",
        status: str = "FAIL",
        compliance: object = ("MITRE ATT&CK", "T1078", "T1078", "CIS 1.1"),
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
