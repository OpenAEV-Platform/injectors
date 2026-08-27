"""Fixtures local to CHK.004 behaviour tests."""

# ruff: noqa: D103

import pytest
from pydantic import SecretStr

from prowler.models.provider_inputs import AwsProviderInput


@pytest.fixture
def provider_input() -> AwsProviderInput:
    return AwsProviderInput(
        provider="aws",
        aws_access_key_id="AKIA_TEST",
        aws_secret_access_key=SecretStr("do-not-leak"),
        aws_account_id="123456789012",
        aws_region="eu-west-1",
    )
