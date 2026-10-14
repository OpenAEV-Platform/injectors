"""Coverage for the credential-reference element appended by provider_fields."""

from __future__ import annotations

import pytest
from pyoaev.contracts.contract_config import (
    ContractFieldKey,
    ContractFieldType,
    ContractReferencedCredential,
)
from pyoaev.credential.types import CredentialType

from prowler.contracts.provider_fields import (
    _PROVIDER_FIELDS,
    CREDENTIAL_MANAGER_PROVIDERS,
    CREDENTIAL_REFERENCE_KEY,
    CREDENTIAL_SOURCE_KEY,
    ProviderName,
    build_provider_fields,
)

# The four providers that declare their own credential text fields. The "all"
# meta-token is intentionally excluded: it has no entry in _PROVIDER_FIELDS.
CREDENTIAL_PROVIDERS: tuple[ProviderName, ...] = ("aws", "azure", "gcp", "kubernetes")

# kubernetes has no cloud CredentialType, so the platform applies no filter.
EXPECTED_CREDENTIAL_TYPE: dict[ProviderName, CredentialType | None] = {
    "aws": CredentialType.CLOUD_AWS,
    "azure": CredentialType.CLOUD_AZURE,
    "gcp": CredentialType.CLOUD_GCP,
    "kubernetes": None,
}


def _credential_reference(provider: ProviderName) -> ContractReferencedCredential:
    """Return the single credential-reference element for one provider."""
    elements = [
        element
        for element in build_provider_fields(provider)
        if element.key == CREDENTIAL_REFERENCE_KEY
    ]
    assert len(elements) == 1
    return elements[0]


def test_module_key_matches_the_pyoaev_immutable_key() -> None:
    """The local constant must track the key pyoaev pins on the element."""
    assert CREDENTIAL_REFERENCE_KEY == ContractFieldKey.CredentialReference.value
    assert ContractReferencedCredential().key == CREDENTIAL_REFERENCE_KEY


def test_every_credential_provider_is_covered_by_the_expectation_table() -> None:
    """A new provider must not silently escape the credential-type assertions."""
    assert set(EXPECTED_CREDENTIAL_TYPE) == set(_PROVIDER_FIELDS)
    assert set(CREDENTIAL_PROVIDERS) == set(_PROVIDER_FIELDS)


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_exactly_one_credential_reference_is_appended(provider: ProviderName) -> None:
    """Each provider gains exactly one credential-reference element."""
    elements = build_provider_fields(provider)
    keys = [element.key for element in elements]
    assert keys.count(CREDENTIAL_REFERENCE_KEY) == 1
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_credential_source_and_reference_lead_the_form(provider: ProviderName) -> None:
    """The credential source select and the picker come before the fields.

    Kubernetes has no credential type: no select, the picker stays last.
    """
    elements = build_provider_fields(provider)
    specification_keys = [spec.key for spec in _PROVIDER_FIELDS[provider]]
    if provider in CREDENTIAL_MANAGER_PROVIDERS:
        expected = [
            CREDENTIAL_SOURCE_KEY,
            CREDENTIAL_REFERENCE_KEY,
            *specification_keys,
        ]
        assert type(elements[1]) is ContractReferencedCredential
    else:
        expected = [*specification_keys, CREDENTIAL_REFERENCE_KEY]
        assert type(elements[-1]) is ContractReferencedCredential
    assert [element.key for element in elements] == expected


@pytest.mark.parametrize("provider", CREDENTIAL_MANAGER_PROVIDERS)
def test_credential_source_select_defaults_to_the_credential_manager(
    provider: ProviderName,
) -> None:
    """A closed, required select: the credential manager or manual credentials."""
    (select,) = [
        e for e in build_provider_fields(provider) if e.key == CREDENTIAL_SOURCE_KEY
    ]
    assert select.mandatory is True
    assert select.defaultValue == ["credential_manager"]
    assert list(select.choices) == ["credential_manager", "manual"]
    assert select.choices["manual"].endswith(" - manual credentials")


@pytest.mark.parametrize("provider", CREDENTIAL_MANAGER_PROVIDERS)
def test_credential_reference_is_required_with_the_credential_manager_only(
    provider: ProviderName,
) -> None:
    """The picker is shown, and required, when the credential manager is chosen."""
    element = _credential_reference(provider)
    manager = {CREDENTIAL_SOURCE_KEY: "credential_manager"}
    assert element.mandatory is False
    assert element.visibleConditionFields == [CREDENTIAL_SOURCE_KEY]
    assert element.visibleConditionValues == manager
    assert element.mandatoryConditionFields == [CREDENTIAL_SOURCE_KEY]
    assert element.mandatoryConditionValues == manager


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_credential_reference_declares_the_expected_wire_shape(
    provider: ProviderName,
) -> None:
    """The element is an optional single-valued credential-reference field."""
    element = _credential_reference(provider)
    assert element.type == ContractFieldType.CredentialReference.value
    assert element.type == "credential-reference"
    assert element.mandatory is False
    assert element.multiple is False
    assert element.label == "Select a credential reference"


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_credential_reference_type_matches_the_provider(
    provider: ProviderName,
) -> None:
    """Provider-to-CredentialType mapping stays aligned with pyoaev."""
    element = _credential_reference(provider)
    assert element.credential_reference_type == EXPECTED_CREDENTIAL_TYPE[provider]


def test_kubernetes_carries_no_credential_type_filter() -> None:
    """Kubernetes is unmapped on purpose: no type means no frontend filter."""
    assert _credential_reference("kubernetes").credential_reference_type is None


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_credential_reference_does_not_collide_with_provider_keys(
    provider: ProviderName,
) -> None:
    """The reserved key must never shadow a provider model field."""
    specification_keys = {spec.key for spec in _PROVIDER_FIELDS[provider]}
    assert CREDENTIAL_REFERENCE_KEY not in specification_keys


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_provider_text_fields_keep_their_specification(provider: ProviderName) -> None:
    """Each provider field keeps its key and label, in specification order."""
    elements = [
        element
        for element in build_provider_fields(provider)
        if element.key not in (CREDENTIAL_SOURCE_KEY, CREDENTIAL_REFERENCE_KEY)
    ]
    for element, specification in zip(
        elements, _PROVIDER_FIELDS[provider], strict=True
    ):
        assert element.key == specification.key
        assert element.label == specification.label
        assert element.mandatoryGroups == []


@pytest.mark.parametrize("provider", CREDENTIAL_MANAGER_PROVIDERS)
def test_credential_fields_are_shown_with_manual_credentials_only(
    provider: ProviderName,
) -> None:
    """The fields a credential provides belong to manual credentials.

    They are shown, and required when the specification says so, only when
    manual credentials are chosen; the other fields are always shown.
    """
    fields = {element.key: element for element in build_provider_fields(provider)}
    manual = {CREDENTIAL_SOURCE_KEY: "manual"}
    for specification in _PROVIDER_FIELDS[provider]:
        element = fields[specification.key]
        if specification.from_credential:
            assert element.mandatory is False
            assert element.visibleConditionValues == manual
            expected = manual if specification.mandatory else []
            assert element.mandatoryConditionValues == expected
        else:
            assert element.mandatory is specification.mandatory
            assert element.visibleConditionFields == []


def test_aws_account_id_stays_mandatory_with_a_reference() -> None:
    """No stored credential carries the AWS account ID."""
    fields = {element.key: element for element in build_provider_fields("aws")}
    assert fields["aws_account_id"].mandatory is True
    assert fields["aws_account_id"].mandatoryGroups == []


def test_kubernetes_fields_stay_mandatory() -> None:
    """No credential type maps to Kubernetes, so no reference can replace them."""
    for element in build_provider_fields("kubernetes")[:-1]:
        assert element.mandatory is True
        assert element.mandatoryGroups == []


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_build_provider_fields_returns_independent_elements(
    provider: ProviderName,
) -> None:
    """Callers mutate conditions per call, so instances must not be shared.

    ``UniversalProwlerContract`` assigns ``visibleConditionFields`` on the
    returned elements, which would leak across contracts if the builder
    returned cached objects.
    """
    first = _credential_reference(provider)
    second = _credential_reference(provider)
    assert first is not second
    assert first == second


# --- Parse boundary: the selector key must never reach the strict model -----

_LEGACY_AWS_FORM = {
    "credential_source": "manual",
    "aws_access_key_id": "AKIAEXAMPLE",
    "aws_secret_access_key": "secret",
    "aws_account_id": "123456789012",
    "aws_region": "eu-west-1",
}


def _registry_contract(route: str) -> object:
    """Resolve one shared registry contract by route name."""
    from prowler.contracts import DEFAULT_PROWLER_CONTRACTS, stable_contract_id

    return DEFAULT_PROWLER_CONTRACTS.resolve(str(stable_contract_id(route)))


@pytest.mark.parametrize("route", ("aws", "aws/s3", "aws/select-service"))
def test_fixed_contract_parse_ignores_the_credential_reference_key(
    route: str,
) -> None:
    """With ``extra="forbid"``, a leaked key would reject every such inject."""
    contract = _registry_contract(route)
    form: dict[str, object] = dict(_LEGACY_AWS_FORM)
    if route == "aws/select-service":
        form["prowler_service"] = "s3"

    expected = contract.parse_input(form)  # type: ignore[attr-defined]
    parsed = contract.parse_input(  # type: ignore[attr-defined]
        {**form, CREDENTIAL_REFERENCE_KEY: "3f1c1e5e-0000-4000-8000-000000000001"}
    )

    assert parsed == expected


def test_universal_contract_parse_ignores_the_credential_reference_key() -> None:
    """The universal parser filters the key on its own candidate path."""
    contract = _registry_contract("universal")
    form = {"prowler_provider": "aws", **_LEGACY_AWS_FORM}

    expected = contract.parse_input(form)  # type: ignore[attr-defined]
    parsed = contract.parse_input(  # type: ignore[attr-defined]
        {**form, CREDENTIAL_REFERENCE_KEY: "3f1c1e5e-0000-4000-8000-000000000001"}
    )

    assert parsed == expected
