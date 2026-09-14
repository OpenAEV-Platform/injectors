"""R11 form-shape checks for the universal contract."""

from __future__ import annotations

import json
from typing import Any, cast

from prowler.contracts import (
    DEFAULT_PROWLER_CONTRACTS,
    UniversalProwlerContract,
    stable_contract_id,
)

PROVIDER_KEY = "prowler_provider"
SERVICE_KEY = "prowler_service"
COMPLIANCE_KEY = "prowler_compliance"
PROVIDERS = ("aws", "azure", "gcp", "kubernetes")

_EXPECTED_PROVIDER_CHOICES = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "kubernetes": "Kubernetes",
}
_EXPECTED_SERVICE_CHOICES = {
    "aws/iam": "IAM (AWS)",
    "aws/s3": "S3 (AWS)",
    "aws/ec2": "EC2 (AWS)",
    "azure/iam": "IAM (Azure)",
    "azure/storage": "Storage (Azure)",
    "gcp/iam": "IAM (GCP)",
    "gcp/compute": "Compute (GCP)",
}
_EXPECTED_COMPLIANCE_CHOICES = {
    "cis/aws": "CIS 3.0 (AWS)",
    "cis/azure": "CIS 3.0 (Azure)",
    "cis/gcp": "CIS 3.0 (GCP)",
    "cis/kubernetes": "CIS 1.12 (Kubernetes)",
    "nis2/aws": "NIS2 (AWS)",
    "nis2/azure": "NIS2 (Azure)",
    "nis2/gcp": "NIS2 (GCP)",
    "iso27001/aws": "ISO 27001:2022 (AWS)",
    "iso27001/azure": "ISO 27001:2022 (Azure)",
    "iso27001/gcp": "ISO 27001:2022 (GCP)",
    "iso27001/kubernetes": "ISO 27001:2022 (Kubernetes)",
    "mitre/aws": "MITRE ATT&CK (AWS)",
    "mitre/azure": "MITRE ATT&CK (Azure)",
    "mitre/gcp": "MITRE ATT&CK (GCP)",
}
_OPTIONAL_AWS_FIELDS = frozenset({"aws_endpoint_url", "aws_session_token"})


def _serialized() -> dict[str, Any]:
    """Return the serialized universal contract content."""
    serialized = DEFAULT_PROWLER_CONTRACTS.contracts()
    item = next(
        entry
        for entry in serialized
        if entry["contract_id"] == str(stable_contract_id("universal"))
    )
    return cast("dict[str, Any]", json.loads(str(item["contract_content"])))


def _expected_credential_fields() -> list[tuple[str, str, str, str, bool]]:
    """Derive the 15 credential fields from the four fixed provider contracts."""
    expected: list[tuple[str, str, str, str, bool]] = []
    for provider in PROVIDERS:
        fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(provider)))
        for element in fixed.build_provider_fields():
            expected.append(
                (provider, element.key, element.label, element.type, element.mandatory)
            )
    return expected


def test_route_table_metadata() -> None:
    """Assert the universal route table entry and stable identity."""
    contract = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id("universal")))
    assert type(contract) is UniversalProwlerContract
    assert contract.contract_id == str(stable_contract_id("universal"))
    assert contract.contract_id == "33234db3-946e-5ba1-8912-6e689b9348b0"
    assert contract.external_id == "prowler:universal"
    assert contract.route_name == "universal"
    assert contract.provider == "all"
    assert contract.family == "universal"
    assert contract.label == "Prowler Universal"
    assert contract.check_filters == ()


def test_serialized_form_has_18_fields_in_exact_order() -> None:
    """Assert exactly the 18 fields of the contract, in that exact order."""
    content = _serialized()
    fields = content["fields"]
    expected_credential = _expected_credential_fields()
    assert len(fields) == 18
    assert [f["key"] for f in fields] == [
        PROVIDER_KEY,
        *(key for _provider, key, _label, _type, _mandatory in expected_credential),
        SERVICE_KEY,
        COMPLIANCE_KEY,
    ]
    assert [f["label"] for f in fields[1:16]] == [
        label for _provider, _key, label, _type, _mandatory in expected_credential
    ]
    assert [f["type"] for f in fields[1:16]] == [
        field_type
        for _provider, _key, _label, field_type, _mandatory in expected_credential
    ]


def test_provider_select_shape_and_conditions_empty() -> None:
    """Assert the mandatory single provider select with default ["aws"]."""
    fields = _serialized()["fields"]
    select = fields[0]
    assert select["key"] == PROVIDER_KEY
    assert select["type"] == "select"
    assert select["mandatory"] is True
    assert select["cardinality"] == "1"
    assert select["defaultValue"] == ["aws"]
    assert select["choices"] == _EXPECTED_PROVIDER_CHOICES
    assert list(select["choices"]) == list(PROVIDERS)
    assert select["visibleConditionFields"] == []
    assert select["visibleConditionValues"] == {}
    assert select["mandatoryConditionFields"] == []
    assert select["mandatoryConditionValues"] == {}


def test_credential_fields_carry_exact_condition_attributes() -> None:
    """Assert visibility and conditional mandatory wiring per provider."""
    fields = _serialized()["fields"][1:16]
    expected_credential = _expected_credential_fields()
    assert len(fields) == 15
    mandatory_count = 0
    for field, (
        provider,
        _key,
        _label,
        _type,
        base_mandatory,
    ) in zip(fields, expected_credential, strict=True):
        assert field["visibleConditionFields"] == [PROVIDER_KEY]
        assert field["visibleConditionValues"] == {PROVIDER_KEY: provider}
        assert field["mandatory"] is False
        if base_mandatory:
            mandatory_count += 1
            assert field["mandatoryConditionFields"] == [PROVIDER_KEY]
            assert field["mandatoryConditionValues"] == {PROVIDER_KEY: provider}
        else:
            assert field["key"] in _OPTIONAL_AWS_FIELDS
            assert field["mandatoryConditionFields"] == []
            assert field["mandatoryConditionValues"] == {}
    assert mandatory_count == 13


def test_scope_selects_are_optional_single_with_empty_defaults() -> None:
    """Assert both scope selects: optional, single, empty default, closed choices."""
    fields = _serialized()["fields"]
    service = fields[16]
    compliance = fields[17]
    assert service["key"] == SERVICE_KEY
    assert compliance["key"] == COMPLIANCE_KEY
    for select in (service, compliance):
        assert select["type"] == "select"
        assert select["mandatory"] is False
        assert select["cardinality"] == "1"
        assert select["defaultValue"] == []
        assert select["visibleConditionFields"] == []
        assert select["visibleConditionValues"] == {}
        assert select["mandatoryConditionFields"] == []
        assert select["mandatoryConditionValues"] == {}
    assert service["choices"] == _EXPECTED_SERVICE_CHOICES
    assert compliance["choices"] == _EXPECTED_COMPLIANCE_CHOICES
    assert len(service["choices"]) == 7
    assert len(compliance["choices"]) == 14


def test_outputs_and_manual_unchanged() -> None:
    """Assert findings+vulnerabilities outputs with the universal labels."""
    content = _serialized()
    outputs = content["outputs"]
    assert {o["type"] for o in outputs} == {"text", "vulnerability"}
    assert {o["field"] for o in outputs} == {"findings", "vulnerabilities"}
    assert all(o["labels"] == ["prowler", "all", "universal"] for o in outputs)
    assert content["manual"] is False
    assert content["external_id"] == "prowler:universal"
    assert content["label"]["en"] == "Prowler Universal"
