"""R01 form-shape checks for the six selectable contracts."""

from __future__ import annotations

import json
from typing import Any, get_args

import pytest

from prowler._core.prowler_client import (AwsServiceSelector,
                                          AzureServiceSelector,
                                          ComplianceSelector,
                                          GcpServiceSelector)
from prowler.contracts import (DEFAULT_PROWLER_CONTRACTS,
                               AwsSelectComplianceContract,
                               AwsSelectServiceContract,
                               AzureSelectComplianceContract,
                               AzureSelectServiceContract,
                               GcpSelectComplianceContract,
                               GcpSelectServiceContract, stable_contract_id)

_ROUTES: tuple[tuple[str, str, str, type[Any], str], ...] = (
    (
        "aws/select-service",
        "aws",
        "prowler_service",
        AwsSelectServiceContract,
        "Prowler AWS Selectable Service",
    ),
    (
        "aws/select-compliance",
        "aws",
        "prowler_compliance",
        AwsSelectComplianceContract,
        "Prowler AWS Selectable Compliance",
    ),
    (
        "azure/select-service",
        "azure",
        "prowler_service",
        AzureSelectServiceContract,
        "Prowler Azure Selectable Service",
    ),
    (
        "azure/select-compliance",
        "azure",
        "prowler_compliance",
        AzureSelectComplianceContract,
        "Prowler Azure Selectable Compliance",
    ),
    (
        "gcp/select-service",
        "gcp",
        "prowler_service",
        GcpSelectServiceContract,
        "Prowler GCP Selectable Service",
    ),
    (
        "gcp/select-compliance",
        "gcp",
        "prowler_compliance",
        GcpSelectComplianceContract,
        "Prowler GCP Selectable Compliance",
    ),
)
_IDS = [route for route, _, _, _, _ in _ROUTES]


def _derived(route: str, provider: str) -> tuple[str, ...]:
    """Return the derived choice values for one selectable route."""
    if route.endswith("select-service"):
        selector = {
            "aws": AwsServiceSelector,
            "azure": AzureServiceSelector,
            "gcp": GcpServiceSelector,
        }[provider]
        return get_args(selector)
    return tuple(
        value
        for value in get_args(ComplianceSelector)
        if value.endswith(f"_{provider}")
    )


@pytest.mark.parametrize(
    ("route", "provider", "key", "cls", "label"), _ROUTES, ids=_IDS
)
def test_route_table_metadata(
    route: str, provider: str, key: str, cls: type[Any], label: str
) -> None:
    """Assert contract IDs, external IDs, labels, and classes match."""
    contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))
    assert type(contract) is cls
    assert contract.contract_id == str(stable_contract_id(route))
    assert contract.external_id == f"prowler:{route}"
    assert contract.route_name == route
    assert contract.provider == provider
    assert contract.family == (
        "service" if route.endswith("select-service") else "compliance"
    )
    assert contract.label == label
    assert contract.check_filters == ()


@pytest.mark.parametrize(
    ("route", "provider", "key", "cls", "label"), _ROUTES, ids=_IDS
)
def test_serialized_form_has_one_closed_select_after_provider_fields(
    route: str, provider: str, key: str, cls: type[Any], label: str
) -> None:
    """Assert the serialized form adds exactly one mandatory single select."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id(route))
    )
    content = json.loads(str(item["contract_content"]))
    fields = content["fields"]
    select_fields = [f for f in fields if f["type"] == "select"]
    assert len(select_fields) == 1
    select = select_fields[0]
    assert select["key"] == key
    assert select["mandatory"] is True
    assert select["cardinality"] == "1"
    derived = list(_derived(route, provider))
    assert select["defaultValue"] == [derived[0]]
    assert list(select["choices"]) == derived
    assert all(select["choices"].values())
    instance = cls()
    provider_fields = instance.build_provider_fields()
    assert [f["key"] for f in fields] == [f.key for f in provider_fields]
    fixed_instance = DEFAULT_PROWLER_CONTRACTS.resolve(
        str(stable_contract_id(provider))
    )
    assert provider_fields[:-1] == fixed_instance.build_provider_fields()
    select_element = provider_fields[-1]
    from prowler.contracts.selectable import STATIC_SELECT_LABELS

    assert select_element.mandatory is True
    assert str(select_element.cardinality) == "1"
    assert select_element.defaultValue == [derived[0]]
    assert select_element.choices == {
        value: STATIC_SELECT_LABELS[value] for value in derived
    }


@pytest.mark.parametrize(
    ("route", "provider", "key", "cls", "label"), _ROUTES, ids=_IDS
)
def test_outputs_unchanged_and_labelled(
    route: str, provider: str, key: str, cls: type[Any], label: str
) -> None:
    """Assert outputs stay findings plus vulnerabilities with route labels."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id(route))
    )
    content = json.loads(str(item["contract_content"]))
    outputs = content["outputs"]
    assert {o["type"] for o in outputs} == {"text", "vulnerability"}
    assert all(route in o["labels"] for o in outputs)
    assert content["manual"] is False
    assert content["contract_id"] == str(stable_contract_id(route))
    assert content["label"]["en"] == label
