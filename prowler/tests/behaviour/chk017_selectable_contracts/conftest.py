"""Local deterministic CHK.017 fixtures."""

from collections.abc import Callable
from typing import Any

import pytest

AWS_FORM: dict[str, str] = {
    "aws_access_key_id": "AKIAEXAMPLEKEYID",
    "aws_secret_access_key": "example-secret",
    "aws_account_id": "123456789012",
    "aws_region": "eu-west-1",
}
AZURE_FORM: dict[str, str] = {
    "azure_tenant_id": "tenant-id",
    "azure_client_id": "client-id",
    "azure_client_secret": "client-secret",
    "azure_subscription_id": "subscription-id",
    "azure_provider": "AzureCloud",
}
GCP_FORM: dict[str, str] = {
    "gcp_service_account_json": '{"type": "service_account"}',
    "gcp_project_id": "project-id",
}


def _ocsf_record(title: str, provider: str, status_code: str) -> dict[str, Any]:
    """Build one minimal valid CHK.005 source record."""
    return {
        "finding_info": {
            "uid": f"check-{title.lower().replace(' ', '-')}",
            "title": title,
            "desc": f"Description for {title}",
        },
        "status": "New",
        "status_code": status_code,
        "severity": "High",
        "resources": [{"uid": "asset-id", "name": "asset-name"}],
        "cloud": {
            "provider": provider,
            "region": "eu-west-1",
            "account": {"uid": "account-placeholder"},
        },
        "remediation": {"desc": "Remediate safely", "references": []},
    }


@pytest.fixture
def ocsf_record_factory() -> Callable[[str, str, str], dict[str, Any]]:
    """Return a factory for minimal valid CHK.005 source records."""

    def make(title: str, provider: str, status_code: str = "PASS") -> dict[str, Any]:
        """Create one record for the given provider."""
        return _ocsf_record(title, provider, status_code)

    return make
