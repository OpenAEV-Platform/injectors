"""R11 form-shape checks for the universal contract."""

from __future__ import annotations

import json
from typing import Any, cast

from prowler.contracts import (
    CREDENTIAL_REFERENCE_KEY,
    CREDENTIAL_SOURCE_KEY,
    DEFAULT_PROWLER_CONTRACTS,
    UniversalProwlerContract,
    stable_contract_id,
)

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
_CREDENTIAL_MANAGER_PROVIDERS = ["aws", "azure", "gcp"]
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
# The fields a stored credential provides: manual credentials only.
_MANUAL_ONLY_FIELDS = frozenset(
    {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_region",
        "aws_session_token",
        "azure_tenant_id",
        "azure_client_id",
        "azure_client_secret",
        "azure_subscription_id",
        "azure_provider",
        "gcp_service_account_json",
        "gcp_project_id",
    }
)


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

    The fixed contracts also expose a credential source select and a
    credential reference: the universal provider select replaces the first,
    and the pyoaev-pinned key of the second allows exactly one copy. Both are
    excluded here; the reference is asserted on its own in
    ``test_single_credential_reference_for_the_credential_manager``.
    """
    expected: list[tuple[str, str, str, str, bool]] = []
    for provider in PROVIDERS:
        fixed = DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(provider)))
        for element in fixed.build_provider_fields():
            if element.key in (CREDENTIAL_REFERENCE_KEY, CREDENTIAL_SOURCE_KEY):
                continue
            # Required on its own, or with manual credentials only.
            mandatory = element.mandatory or bool(element.mandatoryConditionFields)
            expected.append(
                (provider, element.key, element.label, element.type, mandatory)
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


def test_serialized_form_has_22_fields_in_exact_order() -> None:
    """Assert exactly the 22 fields of the contract, in that exact order."""
    content = _serialized()
    fields = content["fields"]
    expected_credential = _expected_credential_fields()
    assert len(fields) == 22
    assert [f["key"] for f in fields] == [
        PROVIDER_KEY,
        CREDENTIAL_SOURCE_KEY,
        CREDENTIAL_REFERENCE_KEY,
        *(key for _provider, key, _label, _type, _mandatory in expected_credential),
        *SERVICE_KEYS.values(),
        COMPLIANCE_KEY,
    ]
    assert [f["label"] for f in fields[3:18]] == [
        label for _provider, _key, label, _type, _mandatory in expected_credential
    ]
    assert [f["type"] for f in fields[3:18]] == [
        field_type
        for _provider, _key, _label, field_type, _mandatory in expected_credential
    ]


def test_single_credential_reference_for_the_credential_manager() -> None:
    """Assert one credential reference, shown and required for the manager."""
    fields = _serialized()["fields"]
    references = [f for f in fields if f["key"] == CREDENTIAL_REFERENCE_KEY]
    assert len(references) == 1
    reference = references[0]
    assert fields.index(reference) == 2
    assert reference["type"] == "credential-reference"
    assert reference["mandatory"] is False
    assert reference["cardinality"] == "1"
    # The operator selects the provider through PROVIDER_KEY, so the universal
    # contract deliberately carries no CredentialType filter.
    assert reference["credential_reference_type"] is None
    # Shown for a provider with a credential type and the credential manager;
    # required with the credential manager (the select is cleared otherwise).
    assert reference["visibleConditionFields"] == [PROVIDER_KEY, CREDENTIAL_SOURCE_KEY]
    assert reference["visibleConditionValues"] == {
        PROVIDER_KEY: _CREDENTIAL_MANAGER_PROVIDERS,
        CREDENTIAL_SOURCE_KEY: "credential_manager",
    }
    assert reference["mandatoryConditionFields"] == [CREDENTIAL_SOURCE_KEY]
    assert reference["mandatoryConditionValues"] == {
        CREDENTIAL_SOURCE_KEY: "credential_manager"
    }


def test_credential_source_select_is_shown_for_credential_providers() -> None:
    """Assert the credential source select of the providers with a type."""
    fields = _serialized()["fields"]
    select = fields[1]
    assert select["key"] == CREDENTIAL_SOURCE_KEY
    assert select["type"] == "select"
    assert select["defaultValue"] == ["credential_manager"]
    assert select["choices"] == {
        "credential_manager": "Credential manager",
        "manual": "Manual credentials",
    }
    condition = {PROVIDER_KEY: _CREDENTIAL_MANAGER_PROVIDERS}
    assert select["mandatory"] is False
    assert select["visibleConditionValues"] == condition
    assert select["mandatoryConditionValues"] == condition


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
    assert list(select["choices"]) == list(_EXPECTED_PROVIDER_CHOICES)
    assert select["visibleConditionFields"] == []
    assert select["visibleConditionValues"] == {}
    assert select["mandatoryConditionFields"] == []
    assert select["mandatoryConditionValues"] == {}


def test_credential_fields_carry_exact_condition_attributes() -> None:
    """Assert visibility and conditional mandatory wiring per provider."""
    fields = _serialized()["fields"][3:18]
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
        assert field["mandatory"] is False
        assert field["mandatoryGroups"] == []
        if field["key"] in _MANUAL_ONLY_FIELDS:
            # Shown with manual credentials, never marked required: the
            # platform checks each condition alone, so the provider and the
            # source together cannot make it required; checked at execution.
            assert field["visibleConditionValues"] == {
                PROVIDER_KEY: provider,
                CREDENTIAL_SOURCE_KEY: "manual",
            }
            assert field["mandatoryConditionFields"] == []
            continue
        assert field["visibleConditionValues"] == {PROVIDER_KEY: provider}
        if base_mandatory:
            mandatory_count += 1
            assert field["mandatoryConditionFields"] == [PROVIDER_KEY]
            assert field["mandatoryConditionValues"] == {PROVIDER_KEY: provider}
        else:
            assert field["key"] == "aws_endpoint_url"
            assert field["mandatoryConditionFields"] == []
    # The AWS account ID and the Kubernetes fields: no credential carries them.
    assert mandatory_count == 3


def test_scope_selects_are_conditioned_single_with_explicit_none_defaults() -> None:
    """Assert provider services and global compliance use an explicit none choice."""
    fields = _serialized()["fields"]
    services = fields[18:21]
    compliance = fields[21]
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
