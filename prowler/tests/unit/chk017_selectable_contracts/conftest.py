"""Local CHK.017 selectable-contract fixtures."""

import pytest


@pytest.fixture
def provider_forms() -> dict[str, dict[str, str]]:
    """Return one valid form per selectable provider."""
    return {
        "aws": {
            "credential_source": "manual",
            "aws_access_key_id": "AKIAEXAMPLEKEYID",
            "aws_secret_access_key": "example-secret",
            "aws_account_id": "123456789012",
            "aws_region": "eu-west-1",
        },
        "azure": {
            "credential_source": "manual",
            "azure_tenant_id": "tenant-id",
            "azure_client_id": "client-id",
            "azure_client_secret": "client-secret",
            "azure_subscription_id": "subscription-id",
            "azure_provider": "AzureCloud",
        },
        "gcp": {
            "credential_source": "manual",
            "gcp_service_account_json": '{"type": "service_account"}',
            "gcp_project_id": "project-id",
        },
    }
