"""Local CHK.006 executable-base fixtures."""

import pytest

from prowler.models.findings import OpenAevFinding


@pytest.fixture
def findings() -> tuple[OpenAevFinding, ...]:
    """Return one finding for every projected expectation result."""
    def finding(name: str, result: str) -> OpenAevFinding:
        return OpenAevFinding(
            type=f"check-{name}",
            value=f"{name} finding",
            expectation_result=result,
            severity="HIGH",
            severity_weight=3,
            asset_reference=f"resource-{name}",
            asset_name=f"asset-{name}",
            cloud_provider="aws",
            region="eu-west-1",
            cloud_account="account-placeholder",
            compliance_tags=("cis", "nis2"),
            remediation=f"Remediate {name}",
            remediation_url="https://example.invalid/remediation",
            description=f"Description {name}",
        )

    return (
        finding("success", "SUCCESS"),
        finding("failed", "FAILED"),
        finding("ignored", "IGNORED"),
    )
