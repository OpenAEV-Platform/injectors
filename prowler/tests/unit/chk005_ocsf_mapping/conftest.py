"""Local fixtures for CHK.005 mapping units."""

from copy import deepcopy
from typing import Any

import pytest


@pytest.fixture
def copy_record():
    """Return isolated representative Prowler 5.36 records."""
    record: dict[str, Any] = {
        "finding_info": {"uid": "uid", "title": "title", "desc": "description"},
        "status": "PASS",
        "severity": "high",
        "resources": [{"uid": "resource", "name": "resource name"}],
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {"uid": "account"},
        },
        "unmapped": {"compliance": {}},
        "remediation": {"desc": "fix", "references": ["https://example.test"]},
    }

    def factory() -> dict[str, Any]:
        return deepcopy(record)

    return factory
