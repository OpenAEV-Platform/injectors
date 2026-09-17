"""Coverage for the credential-reference element appended by provider_fields."""

from __future__ import annotations

import pytest
from pyoaev.contracts.contract_config import (ContractFieldKey,
                                              ContractFieldType,
                                              ContractReferencedCredential)
from pyoaev.credential.types import CredentialType

from prowler.contracts.provider_fields import (_PROVIDER_FIELDS,
                                               CREDENTIAL_REFERENCE_KEY,
                                               ProviderName,
                                               build_provider_fields)

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
def test_credential_reference_is_appended_last(provider: ProviderName) -> None:
    """The element is appended after the provider's own credential fields."""
    elements = build_provider_fields(provider)
    specification_keys = [spec.key for spec in _PROVIDER_FIELDS[provider]]
    assert [element.key for element in elements] == [
        *specification_keys,
        CREDENTIAL_REFERENCE_KEY,
    ]
    assert type(elements[-1]) is ContractReferencedCredential


@pytest.mark.parametrize("provider", CREDENTIAL_PROVIDERS)
def test_credential_reference_declares_the_expected_wire_shape(
    provider: ProviderName,
) -> None:
    """The element is a mandatory single-valued credential-reference field."""
    element = _credential_reference(provider)
    assert element.type == ContractFieldType.CredentialReference.value
    assert element.type == "credential-reference"
    assert element.mandatory is True
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
def test_provider_text_fields_are_left_untouched(provider: ProviderName) -> None:
    """Appending the element must not alter the existing credential fields."""
    elements = build_provider_fields(provider)
    for element, specification in zip(
        elements[:-1], _PROVIDER_FIELDS[provider], strict=True
    ):
        assert element.key == specification.key
        assert element.label == specification.label
        assert element.mandatory is specification.mandatory


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
