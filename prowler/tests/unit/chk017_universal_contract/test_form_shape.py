"""R11 form-shape checks for the universal contract."""

from __future__ import annotations

import json
from typing import Any, cast

from prowler.contracts import (CREDENTIAL_REFERENCE_KEY,
                               DEFAULT_PROWLER_CONTRACTS,
                               UniversalProwlerContract, stable_contract_id)

PROVIDER_KEY = "prowler_provider"
SERVICE_KEYS = {
    "aws": "prowler_service_aws",
    "azure": "prowler_service_azure",
    "gcp": "prowler_service_gcp",
}
COMPLIANCE_KEY = "prowler_compliance"
PROVIDERS = ("aws", "azure", "gcp", "kubernetes")

_EXPECTED_PROVIDER_CHOICES = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "kubernetes": "Kubernetes",
}
_EXPECTED_SERVICE_CHOICES = {
    "aws": {
        "__none__": "None (base scan)",
        "aws/iam": "IAM (AWS)",
        "aws/s3": "S3 (AWS)",
        "aws/ec2": "EC2 (AWS)",
    },
    "azure": {
        "__none__": "None (base scan)",
        "azure/iam": "IAM (Azure)",
        "azure/storage": "Storage (Azure)",
    },
    "gcp": {
        "__none__": "None (base scan)",
        "gcp/iam": "IAM (GCP)",
        "gcp/compute": "Compute (GCP)",
    },
}
_EXPECTED_COMPLIANCE_CHOICES = {
    "__none__": "None (base scan)",
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
    """Derive the 15 credential fields from the four fixed provider contracts.

    The fixed contracts also expose a credential reference, but its key is
    pinned by pyoaev, so the universal form carries exactly one unconditioned
    copy instead of one per provider. It is excluded here and asserted on its
    own in ``test_single_unconditioned_credential_reference``.
    """
    expected: list[tuple[str, str, str, str, bool]] = []
    for provider in PROVIDERS:
        fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(provider)))
        for element in fixed.build_provider_fields():
            if element.key == CREDENTIAL_REFERENCE_KEY:
                continue
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


def test_serialized_form_has_21_fields_in_exact_order() -> None:
    """Assert exactly the 21 fields of the contract, in that exact order."""
    content = _serialized()
    fields = content["fields"]
    expected_credential = _expected_credential_fields()
    assert len(fields) == 21
    assert [f["key"] for f in fields] == [
        PROVIDER_KEY,
        CREDENTIAL_REFERENCE_KEY,
        *(key for _provider, key, _label, _type, _mandatory in expected_credential),
        *SERVICE_KEYS.values(),
        COMPLIANCE_KEY,
    ]
    assert [f["label"] for f in fields[2:17]] == [
        label for _provider, _key, label, _type, _mandatory in expected_credential
    ]
    assert [f["type"] for f in fields[2:17]] == [
        field_type
        for _provider, _key, _label, field_type, _mandatory in expected_credential
    ]


def test_single_unconditioned_credential_reference() -> None:
    """Assert one always-visible credential reference with no provider filter."""
    fields = _serialized()["fields"]
    references = [f for f in fields if f["key"] == CREDENTIAL_REFERENCE_KEY]
    assert len(references) == 1
    reference = references[0]
    assert fields.index(reference) == 1
    assert reference["type"] == "credential-reference"
    assert reference["mandatory"] is True
    assert reference["multiple"] is False
    # The operator selects the provider through PROVIDER_KEY, so the universal
    # contract deliberately carries no CredentialType filter.
    assert reference["credential_reference_type"] is None
    assert reference["visibleConditionFields"] == []
    assert reference["visibleConditionValues"] == []
    assert reference["mandatoryConditionFields"] == []
    assert reference["mandatoryConditionValues"] == []


def test_form_field_keys_are_unique() -> None:
    """Assert the pinned credential-reference key collides with nothing."""
    keys = [f["key"] for f in _serialized()["fields"]]
    assert len(keys) == len(set(keys))


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
    fields = _serialized()["fields"][2:17]
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


def test_scope_selects_are_conditioned_single_with_explicit_none_defaults() -> None:
    """Assert provider services and global compliance use an explicit none choice."""
    fields = _serialized()["fields"]
    services = fields[17:20]
    compliance = fields[20]
    assert [service["key"] for service in services] == list(SERVICE_KEYS.values())
    assert compliance["key"] == COMPLIANCE_KEY
    for select in (*services, compliance):
        assert select["type"] == "select"
        assert select["mandatory"] is False
        assert select["cardinality"] == "1"
        assert select["defaultValue"] == ["__none__"]
        assert select["mandatoryConditionFields"] == []
        assert select["mandatoryConditionValues"] == {}
    for provider, service in zip(("aws", "azure", "gcp"), services, strict=True):
        assert service["visibleConditionFields"] == [PROVIDER_KEY]
        assert service["visibleConditionValues"] == {PROVIDER_KEY: provider}
        assert service["choices"] == _EXPECTED_SERVICE_CHOICES[provider]
    assert compliance["visibleConditionFields"] == []
    assert compliance["visibleConditionValues"] == {}
    assert compliance["choices"] == _EXPECTED_COMPLIANCE_CHOICES
    assert [len(service["choices"]) for service in services] == [4, 3, 3]
    assert len(compliance["choices"]) == 15


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
