"""R12 drift-guard checks for the universal scope options."""

from __future__ import annotations

import json
from typing import Any, get_args

from prowler._core.prowler_client import ComplianceSelector
from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    ROUTE_CATALOG,
    UniversalProwlerContract,
    stable_contract_id,
)
from prowler.contracts.selectable import SERVICE_SELECT_VALUES
from prowler.contracts.universal import COMPLIANCE_SCOPE_OPTIONS, SERVICE_SCOPE_OPTIONS

PROVIDER_LABELS = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
_KUBERNETES_LABELS = {
    "cis_1.12_kubernetes": "CIS 1.12 (Kubernetes)",
    "iso27001_2022_kubernetes": "ISO 27001:2022 (Kubernetes)",
}
_STATIC_SERVICE_LABELS = {
    "iam": "IAM",
    "s3": "S3",
    "ec2": "EC2",
    "storage": "Storage",
    "compute": "Compute",
}
_STATIC_COMPLIANCE_LABELS = {
    "cis_3.0_aws": "CIS 3.0 (AWS)",
    "nis2_aws": "NIS2 (AWS)",
    "iso27001_2022_aws": "ISO 27001:2022 (AWS)",
    "mitre_attack_aws": "MITRE ATT&CK (AWS)",
    "cis_3.0_azure": "CIS 3.0 (Azure)",
    "nis2_azure": "NIS2 (Azure)",
    "iso27001_2022_azure": "ISO 27001:2022 (Azure)",
    "mitre_attack_azure": "MITRE ATT&CK (Azure)",
    "cis_3.0_gcp": "CIS 3.0 (GCP)",
    "nis2_gcp": "NIS2 (GCP)",
    "iso27001_2022_gcp": "ISO 27001:2022 (GCP)",
    "mitre_attack_gcp": "MITRE ATT&CK (GCP)",
}
_SELECT_TOKENS = ("select-service", "select-compliance")


def _expected_service_options() -> tuple[tuple[str, str, str], ...]:
    """Recompute the service options from the six contracts' own derivation."""
    return tuple(
        (f"{provider}/{value}", provider, value)
        for provider in ("aws", "azure", "gcp")
        for value in SERVICE_SELECT_VALUES[provider]
    )


def _expected_compliance_options() -> tuple[tuple[str, str, str], ...]:
    """Recompute the compliance options from the literal framework/provider grammar."""
    options: list[tuple[str, str, str]] = []
    for literal in get_args(ComplianceSelector):
        provider = literal.rsplit("_", maxsplit=1)[1]
        framework = literal.rsplit("_", maxsplit=1)[0].split("_", maxsplit=1)[0]
        options.append((f"{framework}/{provider}", provider, literal))
    return tuple(options)


def _catalog_scope_routes(family: str) -> tuple[str, ...]:
    """Return the catalog's fixed routes, excluding the six select routes."""
    return tuple(
        route.route_name
        for route in ROUTE_CATALOG
        if route.family == family and not route.route_name.endswith(_SELECT_TOKENS)
    )


def test_service_options_derive_from_selectable_values() -> None:
    """Assert service options equal the six contracts' derivation, in order."""
    actual = tuple(
        (option.route, option.provider, option.literal)
        for option in SERVICE_SCOPE_OPTIONS
    )
    assert actual == _expected_service_options()
    assert len(actual) == 7


def test_compliance_options_derive_from_selector_literals() -> None:
    """Assert compliance options keep the selector literal source order."""
    actual = tuple(
        (option.route, option.provider, option.literal)
        for option in COMPLIANCE_SCOPE_OPTIONS
    )
    assert actual == _expected_compliance_options()
    assert len(actual) == 14


def test_service_options_equal_catalog_service_routes_in_order() -> None:
    """Assert offered service routes equal the catalog's 7 service routes in order."""
    assert tuple(option.route for option in SERVICE_SCOPE_OPTIONS) == (
        _catalog_scope_routes("service")
    )


def test_compliance_options_equal_catalog_compliance_routes_in_order() -> None:
    """Assert offered compliance routes equal the catalog's 14 routes in order."""
    assert tuple(option.route for option in COMPLIANCE_SCOPE_OPTIONS) == (
        _catalog_scope_routes("compliance")
    )


def test_kubernetes_offers_compliance_only_no_service() -> None:
    """Assert kubernetes contributes no service option and exactly cis + iso27001."""
    assert "kubernetes" not in {option.provider for option in SERVICE_SCOPE_OPTIONS}
    kube = [
        option.literal
        for option in COMPLIANCE_SCOPE_OPTIONS
        if option.provider == "kubernetes"
    ]
    assert kube == ["cis_1.12_kubernetes", "iso27001_2022_kubernetes"]
    kube_routes = {
        option.route
        for option in COMPLIANCE_SCOPE_OPTIONS
        if option.provider == "kubernetes"
    }
    assert kube_routes == {"cis/kubernetes", "iso27001/kubernetes"}


def test_every_service_option_matches_the_fixed_route_selector() -> None:
    """Assert each service option maps to the fixed contract's selector literal."""
    for option in SERVICE_SCOPE_OPTIONS:
        fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(option.route)))
        assert fixed.service_selector == option.literal  # type: ignore[attr-defined]


def test_every_compliance_option_matches_the_fixed_route_selector() -> None:
    """Assert each compliance option maps to the fixed contract's selector literal."""
    for option in COMPLIANCE_SCOPE_OPTIONS:
        fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(option.route)))
        assert fixed.compliance_selector == option.literal  # type: ignore[attr-defined]


def test_serialized_choices_key_derived_routes_in_order() -> None:
    """Assert the serialized scope selects key the derived routes with labels."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id("universal"))
    )
    content: dict[str, Any] = json.loads(str(item["contract_content"]))
    fields = {field["key"]: field for field in content["fields"]}
    compliance_choices = fields["prowler_compliance"]["choices"]
    assert list(compliance_choices) == [
        "__none__",
        *(option.route for option in COMPLIANCE_SCOPE_OPTIONS),
    ]
    for option in SERVICE_SCOPE_OPTIONS:
        service_choices = fields[f"prowler_service_{option.provider}"]["choices"]
        assert list(service_choices) == [
            "__none__",
            *(
                item.route
                for item in SERVICE_SCOPE_OPTIONS
                if item.provider == option.provider
            ),
        ]
        literal = option.literal
        provider_label = PROVIDER_LABELS[option.provider]
        assert service_choices[option.route] == (
            f"{_STATIC_SERVICE_LABELS[literal]} ({provider_label})"
        )
    for option in COMPLIANCE_SCOPE_OPTIONS:
        expected = (
            _KUBERNETES_LABELS[option.literal]
            if option.literal in _KUBERNETES_LABELS
            else _STATIC_COMPLIANCE_LABELS[option.literal]
        )
        assert compliance_choices[option.route] == expected
    routes = [
        option.route for option in (*SERVICE_SCOPE_OPTIONS, *COMPLIANCE_SCOPE_OPTIONS)
    ]
    assert len(routes) == len(set(routes))


def test_single_derivation_site_feeds_form_and_parse(
    provider_forms: dict[str, dict[str, str]],
) -> None:
    """Assert one derivation site feeds both the serialized form and the parse."""
    contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))
    assert type(contract) is UniversalProwlerContract
    for option in SERVICE_SCOPE_OPTIONS:
        contract.parse_input(
            {
                **provider_forms[option.provider],
                "prowler_provider": [option.provider],
                f"prowler_service_{option.provider}": [option.route],
            }
        )
    for option in COMPLIANCE_SCOPE_OPTIONS:
        contract.parse_input(
            {
                **provider_forms[option.provider],
                "prowler_provider": [option.provider],
                "prowler_compliance": [option.route],
            }
        )
