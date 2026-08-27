"""Local deterministic CHK.006 fixtures."""

from typing import Any

import pytest


@pytest.fixture
def ocsf_record() -> dict[str, Any]:
    """Return one minimal valid CHK.005 source record."""
    return {
        "finding_info": {
            "uid": "check-id",
            "title": "Check title",
            "desc": "Description",
        },
        "status": "PASS",
        "severity": "High",
        "resources": [{"uid": "asset-id", "name": "asset-name"}],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "account-placeholder"},
        },
        "remediation": {"desc": "Remediate safely", "references": []},
    }
