"""R02 drift-guard checks between the form and the parse boundary."""

from __future__ import annotations

from typing import get_args

from prowler._core.prowler_client import (
    AwsServiceSelector,
    AzureServiceSelector,
    ComplianceSelector,
    GcpServiceSelector,
)
from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, stable_contract_id
from prowler.contracts.selectable import (
    COMPLIANCE_SELECT_CHOICES,
    COMPLIANCE_SELECT_VALUES,
    SERVICE_SELECT_CHOICES,
    SERVICE_SELECT_VALUES,
)

_SERVICE_SELECTORS = {
    "aws": AwsServiceSelector,
    "azure": AzureServiceSelector,
    "gcp": GcpServiceSelector,
}
_SELECT_ROUTES = (
    ("aws/select-service", "aws", "prowler_service", SERVICE_SELECT_VALUES),
    ("aws/select-compliance", "aws", "prowler_compliance", COMPLIANCE_SELECT_VALUES),
    ("azure/select-service", "azure", "prowler_service", SERVICE_SELECT_VALUES),
    (
        "azure/select-compliance",
        "azure",
        "prowler_compliance",
        COMPLIANCE_SELECT_VALUES,
    ),
    ("gcp/select-service", "gcp", "prowler_service", SERVICE_SELECT_VALUES),
    ("gcp/select-compliance", "gcp", "prowler_compliance", COMPLIANCE_SELECT_VALUES),
)


def test_service_values_derive_from_selector_literals() -> None:
    """Assert service values match the CHK.004 selector literal args."""
    for provider, selector in _SERVICE_SELECTORS.items():
        assert SERVICE_SELECT_VALUES[provider] == get_args(selector)


def test_compliance_values_derive_from_selector_literal_source_order() -> None:
    """Assert compliance values keep the selector literal source order."""
    for provider in ("aws", "azure", "gcp"):
        expected = tuple(
            value
            for value in get_args(ComplianceSelector)
            if value.endswith(f"_{provider}")
        )
        assert COMPLIANCE_SELECT_VALUES[provider] == expected


def test_choices_maps_cover_exactly_the_derived_values() -> None:
    """Assert the choices maps key exactly the derived values."""
    for provider, values in SERVICE_SELECT_VALUES.items():
        assert list(SERVICE_SELECT_CHOICES[provider]) == list(values)
        assert all(SERVICE_SELECT_CHOICES[provider][v] for v in values)
    for provider, values in COMPLIANCE_SELECT_VALUES.items():
        assert list(COMPLIANCE_SELECT_CHOICES[provider]) == list(values)
        assert all(COMPLIANCE_SELECT_CHOICES[provider][v] for v in values)


def test_single_derivation_site_feeds_form_and_parse(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert one derivation site feeds both the form and the parse."""
    for route, provider, key, values_by_provider in _SELECT_ROUTES:
        contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))
        offered = list(contract.build_provider_fields()[-1].choices)
        assert offered == list(values_by_provider[provider])
        for value in values_by_provider[provider]:
            contract.parse_input({**provider_forms[provider], key: [value]})
