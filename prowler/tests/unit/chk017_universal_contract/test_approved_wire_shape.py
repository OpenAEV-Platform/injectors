"""Approved OpenAEV scalar wire shape and universal-select behavior."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    BaseProwlerContract,
    ContractInputError,
    ContractInputIssue,
    stable_contract_id,
)
from prowler.models.provider_inputs import ProviderInput

PROVIDER_KEY = "prowler_provider"
COMPLIANCE_KEY = "prowler_compliance"
NONE = "__none__"
SERVICE_KEYS = {
    "aws": "prowler_service_aws",
    "azure": "prowler_service_azure",
    "gcp": "prowler_service_gcp",
}
SERVICE_ROUTES = {
    "aws": "aws/ec2",
    "azure": "azure/storage",
    "gcp": "gcp/compute",
}
COMPLIANCE_ROUTES = {
    "aws": "cis/aws",
    "azure": "nis2/azure",
    "gcp": "mitre/gcp",
    "kubernetes": "iso27001/kubernetes",
}


def _contract() -> BaseProwlerContract:
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))


def _parse(
    provider_forms: Mapping[str, Mapping[str, str]],
    provider: str,
    **selects: object,
) -> ProviderInput:
    return _contract().parse_input(
        {**provider_forms[provider], PROVIDER_KEY: provider, **selects}
    )


@pytest.mark.parametrize("provider", ("aws", "azure", "gcp", "kubernetes"))
def test_provider_accepts_openaev_scalar_and_singleton_compatibility(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """The cardinality-one UI scalar and legacy singleton list parse identically."""
    contract = _contract()
    scalar = contract.parse_input({**provider_forms[provider], PROVIDER_KEY: provider})
    singleton = contract.parse_input(
        {**provider_forms[provider], PROVIDER_KEY: [provider]}
    )
    assert scalar == singleton


@pytest.mark.parametrize("provider", ("aws", "azure", "gcp"))
def test_active_service_accepts_scalar_and_singleton_route(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert the active provider service accepts both supported wire shapes."""
    key = SERVICE_KEYS[provider]
    route = SERVICE_ROUTES[provider]
    for submitted in (route, [route]):
        parsed = _parse(provider_forms, provider, **{key: submitted})
        assert _contract().safe_request_info(parsed)["filters"] == f"service={route}"


@pytest.mark.parametrize("provider", ("aws", "azure", "gcp", "kubernetes"))
@pytest.mark.parametrize("submitted", (None, "", [], NONE, [NONE]))
def test_optional_select_empty_shapes_and_sentinel_are_base_scope(
    provider: str,
    submitted: object,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert all approved optional empty forms normalize to base scope."""
    selects: dict[str, object] = {COMPLIANCE_KEY: submitted}
    if provider in SERVICE_KEYS:
        selects[SERVICE_KEYS[provider]] = submitted
    parsed = _parse(provider_forms, provider, **selects)
    assert _contract().safe_request_info(parsed)["filters"] == "base"


@pytest.mark.parametrize("provider", ("aws", "azure", "gcp", "kubernetes"))
def test_compliance_accepts_scalar_and_singleton_route(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert global compliance accepts scalar and singleton route values."""
    route = COMPLIANCE_ROUTES[provider]
    for submitted in (route, [route]):
        parsed = _parse(provider_forms, provider, **{COMPLIANCE_KEY: submitted})
        assert _contract().safe_request_info(parsed)["filters"] == f"compliance={route}"


@pytest.mark.parametrize("provider", ("aws", "azure", "gcp", "kubernetes"))
def test_inactive_service_values_are_stripped_before_validation(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert every inactive service key is ignored before validation."""
    inactive = {
        key: object() for owner, key in SERVICE_KEYS.items() if owner != provider
    }
    parsed = _parse(provider_forms, provider, **inactive)
    assert _contract().safe_request_info(parsed)["filters"] == "base"


@pytest.mark.parametrize(
    "submitted, issue",
    (
        (["aws/ec2", "aws/s3"], "select_multiple"),
        ("AWS/EC2", "select_unknown_value"),
        (42, "select_unknown_value"),
        ([["aws/ec2"]], "select_unknown_value"),
    ),
)
def test_active_service_remains_strict_and_value_free(
    submitted: object,
    issue: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert malformed active service values stay strict and value-free."""
    with pytest.raises(ContractInputError) as excinfo:
        _parse(provider_forms, "aws", prowler_service_aws=submitted)
    assert excinfo.value.issues == (
        ContractInputIssue(("prowler_service_aws",), issue),
    )
    assert "aws/ec2" not in str(excinfo.value)


def test_sentinels_normalize_before_real_scope_conflict(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a sentinel cannot conflict with a real compliance route."""
    parsed = _parse(
        provider_forms,
        "aws",
        prowler_service_aws=NONE,
        prowler_compliance="cis/aws",
    )
    assert _contract().safe_request_info(parsed)["filters"] == "compliance=cis/aws"


def test_real_service_and_compliance_still_conflict_value_free(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert two real scopes retain the closed conflict behavior."""
    with pytest.raises(ContractInputError) as excinfo:
        _parse(
            provider_forms,
            "aws",
            prowler_service_aws="aws/ec2",
            prowler_compliance="cis/aws",
        )
    assert excinfo.value.issues == (
        ContractInputIssue(("prowler_service_aws", COMPLIANCE_KEY), "scope_conflict"),
    )
    assert "aws/ec2" not in str(excinfo.value)
    assert "cis/aws" not in str(excinfo.value)


def test_global_compliance_provider_mismatch_remains_rejected(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert global compliance remains bound to the selected provider."""
    with pytest.raises(ContractInputError) as excinfo:
        _parse(provider_forms, "azure", prowler_compliance="cis/aws")
    assert excinfo.value.issues == (
        ContractInputIssue((COMPLIANCE_KEY,), "scope_provider_mismatch"),
    )
    assert "cis/aws" not in str(excinfo.value)
