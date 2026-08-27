"""Local fixtures for CHK.005 behaviour."""

from copy import deepcopy
from typing import Any

import pytest


@pytest.fixture
def ocsf_record() -> dict[str, Any]:
    """Return one representative Prowler 5.36 detection finding."""
    return {
        "finding_info": {
            "uid": "prowler.aws.iam.root_user_access_key",
            "title": "Root user access keys should be removed",
            "desc": "The root user has active access keys.",
        },
        "status": "PASS",
        "severity": "High",
        "resources": [{"uid": "arn:aws:iam::123456789012:root", "name": "root"}],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "123456789012"},
        },
        "unmapped": {
            "compliance": {
                "CIS-1.5": ["1.1", "1.2"],
                "ENS-RD2022": "op.acc.6",
            }
        },
        "remediation": {
            "desc": "Delete the root user access keys.",
            "references": ["https://example.test/remediation"],
        },
    }


@pytest.fixture
def copy_record(ocsf_record: dict[str, Any]):
    """Return a factory that isolates mutable source records."""

    def factory() -> dict[str, Any]:
        return deepcopy(ocsf_record)

    return factory
