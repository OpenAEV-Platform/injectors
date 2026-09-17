"""R13/R14 parse-boundary checks for the universal contract."""

from __future__ import annotations

import pytest

from prowler.contracts import (DEFAULT_PROWLER_CONTRACTS, BaseProwlerContract,
                               ContractInputError, ContractInputIssue,
                               stable_contract_id)
from prowler.models.provider_inputs import AwsProviderInput

PROVIDER_KEY = "prowler_provider"
SERVICE_KEYS = {
    "aws": "prowler_service_aws",
    "azure": "prowler_service_azure",
    "gcp": "prowler_service_gcp",
}
COMPLIANCE_KEY = "prowler_compliance"
PROVIDERS = ("aws", "azure", "gcp", "kubernetes")
SERVICE_ROUTES = (
    "aws/iam",
    "aws/s3",
    "aws/ec2",
    "azure/iam",
    "azure/storage",
    "gcp/iam",
    "gcp/compute",
)
COMPLIANCE_ROUTES = (
    "cis/aws",
    "cis/azure",
    "cis/gcp",
    "cis/kubernetes",
    "nis2/aws",
    "nis2/azure",
    "nis2/gcp",
    "iso27001/aws",
    "iso27001/azure",
    "iso27001/gcp",
    "iso27001/kubernetes",
    "mitre/aws",
    "mitre/azure",
    "mitre/gcp",
)
_SCOPE_CASES = (
    *((provider, key, SERVICE_ROUTES) for provider, key in SERVICE_KEYS.items()),
    *((provider, COMPLIANCE_KEY, COMPLIANCE_ROUTES) for provider in PROVIDERS),
)
# One offered service and compliance route for each provider that offers both.
_BOTH_SCOPE_PROVIDERS = {
    "aws": ("aws/iam", "cis/aws"),
    "azure": ("azure/iam", "cis/azure"),
    "gcp": ("gcp/iam", "cis/gcp"),
}
_MISMATCH_CASES = (
    ("azure", SERVICE_KEYS["azure"], "aws/iam"),
    ("aws", SERVICE_KEYS["aws"], "azure/storage"),
    ("gcp", SERVICE_KEYS["gcp"], "aws/s3"),
    ("aws", COMPLIANCE_KEY, "cis/gcp"),
    ("kubernetes", COMPLIANCE_KEY, "cis/aws"),
    ("gcp", COMPLIANCE_KEY, "iso27001/aws"),
)


def _contract() -> BaseProwlerContract:
    """Resolve the shared universal registry instance."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))


def _fixed(route: str) -> BaseProwlerContract:
    """Resolve one shared fixed registry instance by route name."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


@pytest.mark.parametrize("provider", PROVIDERS)
def test_provider_select_parses_each_provider_to_strict_model(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert a valid provider select parses to the exact strict provider model."""
    contract = _contract()
    form = {**provider_forms[provider], PROVIDER_KEY: [provider]}
    parsed = contract.parse_input(form)
    fixed = _fixed(provider)
    expected = fixed.parse_input(dict(provider_forms[provider]))
    assert type(parsed) is type(expected)
    assert parsed == expected
    # Explicit empty scope selects mean the same "none" scope.
    empty_scopes: dict[str, list[str]] = {COMPLIANCE_KEY: []}
    if provider in SERVICE_KEYS:
        empty_scopes[SERVICE_KEYS[provider]] = []
    parsed_empty = contract.parse_input({**form, **empty_scopes})
    assert parsed_empty == expected


@pytest.mark.parametrize("provider", PROVIDERS)
def test_missing_or_empty_provider_select_reports_select_missing(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert a missing or empty provider select reports select_missing."""
    contract = _contract()
    cases = (
        dict(provider_forms[provider]),
        {**provider_forms[provider], PROVIDER_KEY: ""},
        {**provider_forms[provider], PROVIDER_KEY: []},
        {**provider_forms[provider], PROVIDER_KEY: None},
    )
    for form in cases:
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (
            ContractInputIssue((PROVIDER_KEY,), "select_missing"),
        )


@pytest.mark.parametrize("provider", PROVIDERS)
def test_multi_element_provider_select_reports_select_multiple(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert a multi-element provider select reports select_multiple."""
    contract = _contract()
    for submitted in (
        list(PROVIDERS[:2]),
        [provider, provider],
        ["provider-canary-a", "provider-canary-b"],
    ):
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input({**provider_forms[provider], PROVIDER_KEY: submitted})
        assert excinfo.value.issues == (
            ContractInputIssue((PROVIDER_KEY,), "select_multiple"),
        )
        assert "provider-canary-a" not in str(excinfo.value)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_unknown_provider_value_reports_select_unknown_value(
    provider: str, provider_forms: dict[str, dict[str, str]]
) -> None:
    """Assert an unknown single provider value reports select_unknown_value."""
    contract = _contract()
    cases = (
        ["provider-canary-unknown"],
        [provider.upper()],
        [f" {provider}"],
        [f"{provider} "],
        [f"{provider}-x"],
        [123],
        [None],
        [""],
    )
    for submitted in cases:
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input({**provider_forms[provider], PROVIDER_KEY: submitted})
        assert excinfo.value.issues == (
            ContractInputIssue((PROVIDER_KEY,), "select_unknown_value"),
        )
        message = str(excinfo.value)
        for element in submitted:
            if isinstance(element, str) and element.strip():
                assert element.strip() not in message


@pytest.mark.parametrize(("provider", "key", "routes"), _SCOPE_CASES)
def test_scope_select_malformed_or_unknown_scalar_reports_unknown_value(
    provider: str,
    key: str,
    routes: tuple[str, ...],
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert malformed or unknown scalar scope values report unknown value."""
    contract = _contract()
    for submitted in ("scope-canary-raw", 42):
        form = {
            **provider_forms[provider],
            PROVIDER_KEY: [provider],
            key: submitted,
        }
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (
            ContractInputIssue((key,), "select_unknown_value"),
        )
        assert "scope-canary-raw" not in str(excinfo.value)


@pytest.mark.parametrize(("provider", "key", "routes"), _SCOPE_CASES)
def test_scope_select_multiple_reports_select_multiple(
    provider: str,
    key: str,
    routes: tuple[str, ...],
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a multi-element scope select reports select_multiple."""
    contract = _contract()
    for submitted in (
        [routes[0], routes[1]],
        [routes[0], routes[0]],
        ["scope-canary-a", "scope-canary-b"],
    ):
        form = {
            **provider_forms[provider],
            PROVIDER_KEY: [provider],
            key: submitted,
        }
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (ContractInputIssue((key,), "select_multiple"),)
        assert "scope-canary-a" not in str(excinfo.value)


@pytest.mark.parametrize(("provider", "key", "routes"), _SCOPE_CASES)
def test_scope_unknown_value_reports_select_unknown_value(
    provider: str,
    key: str,
    routes: tuple[str, ...],
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert an unknown scope value reports select_unknown_value at the scope key."""
    contract = _contract()
    valid = routes[0]
    cases = (
        ["scope-canary-unknown"],
        [valid.upper()],
        [f" {valid}"],
        [f"{valid} "],
        [f"{valid}-x"],
        ["whatever/unknown"],
        [123],
        [None],
        [""],
    )
    for submitted in cases:
        form = {
            **provider_forms[provider],
            PROVIDER_KEY: [provider],
            key: submitted,
        }
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (
            ContractInputIssue((key,), "select_unknown_value"),
        )
        message = str(excinfo.value)
        for element in submitted:
            if isinstance(element, str) and element.strip():
                assert element.strip() not in message


_BOTH_SCOPE_CASES = tuple(
    (provider, service, compliance)
    for provider, (service, compliance) in sorted(_BOTH_SCOPE_PROVIDERS.items())
)


@pytest.mark.parametrize(
    ("provider", "service", "compliance"),
    _BOTH_SCOPE_CASES,
)
def test_both_scopes_set_reports_single_scope_conflict(
    provider: str,
    service: str,
    compliance: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert both scope selects set is one closed conflict at the two locations."""
    contract = _contract()
    form = {
        **provider_forms[provider],
        PROVIDER_KEY: [provider],
        SERVICE_KEYS[provider]: [service],
        COMPLIANCE_KEY: [compliance],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEYS[provider], COMPLIANCE_KEY), "scope_conflict"),
    )
    message = str(excinfo.value)
    assert service not in message
    assert compliance not in message


@pytest.mark.parametrize(("provider", "key", "value"), _MISMATCH_CASES)
def test_scope_provider_mismatch_reports_closed_type(
    provider: str,
    key: str,
    value: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a scope whose provider disagrees reports scope_provider_mismatch."""
    contract = _contract()
    form = {
        **provider_forms[provider],
        PROVIDER_KEY: [provider],
        key: [value],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((key,), "scope_provider_mismatch"),
    )
    assert value not in str(excinfo.value)


def test_provider_key_rejected_first_even_with_invalid_selects(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the provider key is rejected first, even with invalid selects."""
    contract = _contract()
    form = {
        **provider_forms["aws"],
        PROVIDER_KEY: ["provider-canary-bad"],
        SERVICE_KEYS["aws"]: ["scope-canary-bad"],
        "provider": "aws",
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )
    assert "provider-canary-bad" not in str(excinfo.value)
    assert "scope-canary-bad" not in str(excinfo.value)


def test_select_validation_precedes_provider_model_validation(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a scope issue is reported alone while the model would also fail."""
    contract = _contract()
    form = {
        **{
            key: value
            for key, value in provider_forms["aws"].items()
            if key != "aws_region"
        },
        PROVIDER_KEY: ["aws"],
        SERVICE_KEYS["aws"]: ["scope-canary-bad"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEYS["aws"],), "select_unknown_value"),
    )
    assert "scope-canary-bad" not in str(excinfo.value)


def test_conflict_precedes_mismatch(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the both-set conflict is reported before any provider-scope mismatch."""
    contract = _contract()
    form = {
        **provider_forms["azure"],
        PROVIDER_KEY: ["azure"],
        SERVICE_KEYS["azure"]: ["aws/iam"],
        COMPLIANCE_KEY: ["iso27001/aws"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEYS["azure"], COMPLIANCE_KEY), "scope_conflict"),
    )


def test_structural_issues_precede_conflict(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a structural select issue is reported before the both-set conflict."""
    contract = _contract()
    form = {
        **provider_forms["gcp"],
        PROVIDER_KEY: ["gcp"],
        SERVICE_KEYS["gcp"]: ["gcp/iam", "gcp/compute"],
        COMPLIANCE_KEY: ["iso27001/gcp"],
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue((SERVICE_KEYS["gcp"],), "select_multiple"),
    )


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("mode", ("absent", "empty", "non-empty"))
def test_wrong_provider_fields_stripped_without_issues(
    provider: str,
    mode: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert non-selected-provider fields are stripped, never validated or reported."""
    contract = _contract()
    foreign_keys = tuple(
        key for other in PROVIDERS if other != provider for key in provider_forms[other]
    )
    if mode == "absent":
        form: dict[str, object] = {PROVIDER_KEY: [provider]}
    elif mode == "empty":
        form = {key: "" for key in foreign_keys}
        form[PROVIDER_KEY] = [provider]
    else:
        form = {
            **{
                key: value
                for other in PROVIDERS
                if other != provider
                for key, value in provider_forms[other].items()
            },
            PROVIDER_KEY: [provider],
        }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    fixed = _fixed(provider)
    with pytest.raises(ContractInputError) as fixed_error:
        fixed.parse_input({})
    assert excinfo.value.issues == fixed_error.value.issues
    for key in foreign_keys:
        assert not any(key in issue.location for issue in excinfo.value.issues)


def test_aws_empty_optional_normalization_only_when_aws_selected(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert AWS empty-optional normalization matches the fixed aws boundary."""
    aws_form = {
        **provider_forms["aws"],
        "aws_endpoint_url": "",
        "aws_session_token": "",
    }
    fixed = _fixed("aws")
    expected = fixed.parse_input(dict(aws_form))
    contract = _contract()
    parsed = contract.parse_input({**aws_form, PROVIDER_KEY: ["aws"]})
    assert parsed == expected
    assert isinstance(parsed, AwsProviderInput)
    assert parsed.aws_endpoint_url is None
    assert parsed.aws_session_token is None
