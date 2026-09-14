"""R03 parse-boundary checks for the selectable contracts."""

from __future__ import annotations

import pytest

from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    BaseProwlerContract,
    ContractInputError,
    ContractInputIssue,
    stable_contract_id,
)
from prowler.models.provider_inputs import AwsProviderInput

_ROUTES = (
    ("aws/select-service", "aws", "prowler_service"),
    ("aws/select-compliance", "aws", "prowler_compliance"),
    ("azure/select-service", "azure", "prowler_service"),
    ("azure/select-compliance", "azure", "prowler_compliance"),
    ("gcp/select-service", "gcp", "prowler_service"),
    ("gcp/select-compliance", "gcp", "prowler_compliance"),
)
_IDS = [route for route, _, _ in _ROUTES]


def _contract(route: str) -> BaseProwlerContract:
    """Resolve one shared registry instance by route name."""
    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


def _first_choice(route: str) -> str:
    """Return the first offered choice for one selectable route."""
    return str(list(_contract(route).build_provider_fields()[-1].choices)[0])


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_valid_single_selection_parses_to_strict_provider_model(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a valid selection parses to the exact strict provider model."""
    contract = _contract(route)
    value = _first_choice(route)
    parsed = contract.parse_input({**provider_forms[provider], key: [value]})
    fixed = _contract(provider)
    expected = fixed.parse_input(dict(provider_forms[provider]))
    assert type(parsed) is type(expected)
    assert parsed == expected


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_missing_or_nonlist_select_reports_select_missing(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert missing or non-list selects report select_missing."""
    contract = _contract(route)
    cases = (
        dict(provider_forms[provider]),
        {**provider_forms[provider], key: "select-canary-raw"},
        {**provider_forms[provider], key: []},
        {**provider_forms[provider], key: None},
    )
    for form in cases:
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input(form)
        assert excinfo.value.issues == (ContractInputIssue((key,), "select_missing"),)
        assert "select-canary-raw" not in str(excinfo.value)


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_multi_element_select_reports_select_multiple(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert multi-element selects report select_multiple."""
    contract = _contract(route)
    choices = list(contract.build_provider_fields()[-1].choices)
    for submitted in (
        choices[:2],
        choices + [choices[0]],
        ["select-canary-a", "select-canary-b"],
    ):
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input({**provider_forms[provider], key: submitted})
        assert excinfo.value.issues == (ContractInputIssue((key,), "select_multiple"),)
        assert "select-canary-a" not in str(excinfo.value)


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_unknown_single_value_reports_select_unknown_value(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert unknown single values report select_unknown_value."""
    contract = _contract(route)
    valid = _first_choice(route)
    cases = (
        ["select-canary-unknown"],
        [valid.upper()],
        [f" {valid}"],
        [f"{valid} "],
        [valid + "-x"],
        [123],
        [None],
        [""],
    )
    for submitted in cases:
        with pytest.raises(ContractInputError) as excinfo:
            contract.parse_input({**provider_forms[provider], key: submitted})
        assert excinfo.value.issues == (
            ContractInputIssue((key,), "select_unknown_value"),
        )
        message = str(excinfo.value)
        for element in submitted:
            if isinstance(element, str) and element.strip():
                assert element.strip() not in message


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_provider_key_rejected_first_even_with_invalid_select(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert the provider key is rejected first with an invalid select."""
    contract = _contract(route)
    form = {
        **provider_forms[provider],
        key: ["select-canary-bad"],
        "provider": provider,
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (
        ContractInputIssue(("provider",), "extra_forbidden"),
    )


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_select_issue_precedes_provider_model_issues(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert a select issue precedes provider-model issues."""
    contract = _contract(route)
    other = next(p for p in provider_forms if p != provider)
    foreign_key = next(iter(provider_forms[other]))
    form = {
        **provider_forms[provider],
        key: ["select-canary-bad"],
        foreign_key: "select-canary-foreign",
    }
    with pytest.raises(ContractInputError) as excinfo:
        contract.parse_input(form)
    assert excinfo.value.issues == (ContractInputIssue((key,), "select_unknown_value"),)
    assert "select-canary-foreign" not in str(excinfo.value)


@pytest.mark.parametrize(("route", "provider", "key"), _ROUTES, ids=_IDS)
def test_unknown_extra_keys_keep_pydantic_structure(
    route: str,
    provider: str,
    key: str,
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert unknown extra keys keep the pydantic-safe structure."""
    contract = _contract(route)
    other = next(p for p in provider_forms if p != provider)
    foreign_key = next(iter(provider_forms[other]))
    valid = _first_choice(route)
    form = {
        **provider_forms[provider],
        key: [valid],
        foreign_key: "select-canary-foreign",
    }
    fixed = _contract(provider)
    with pytest.raises(ContractInputError) as fixed_error:
        fixed.parse_input(
            {**provider_forms[provider], foreign_key: "select-canary-foreign"}
        )
    with pytest.raises(ContractInputError) as selectable_error:
        contract.parse_input(form)
    assert selectable_error.value.issues == fixed_error.value.issues
    assert "select-canary-foreign" not in str(selectable_error.value)


def test_aws_empty_optional_normalization_unchanged(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert AWS empty-optional normalization is unchanged."""
    aws_form = {
        **provider_forms["aws"],
        "aws_endpoint_url": "",
        "aws_session_token": "",
    }
    fixed = _contract("aws")
    expected = fixed.parse_input(dict(aws_form))
    contract = _contract("aws/select-service")
    parsed = contract.parse_input({**aws_form, "prowler_service": ["iam"]})
    assert parsed == expected
    assert isinstance(parsed, AwsProviderInput)
    assert parsed.aws_endpoint_url is None
    assert parsed.aws_session_token is None
