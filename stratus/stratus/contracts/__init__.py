"""Stratus Red Team contracts package.

Public API:
- ``build_all_contracts()``: returns one detonation contract per Stratus
  platform (AWS, Azure, Entra ID, GCP, Kubernetes, EKS) for injector
  registration.
- ``PLATFORMS_BY_CONTRACT``: maps a contract id back to its platform spec so the
  injector can resolve credentials and technique wiring at detonation time.
"""

from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    ContractTextArea,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

from stratus.contracts.platforms import (  # noqa: F401 (re-exported)
    PLATFORMS,
    PLATFORMS_BY_CONTRACT,
    CredField,
    PlatformSpec,
)

CONTRACT_TYPE = "openaev_stratus"

# Field keys shared by every platform contract.
TECHNIQUE_FIELD_KEY = "technique_id"
CUSTOM_TECHNIQUE_FIELD_KEY = "custom_technique_id"

# Stratus Red Team brand colors (navy badge / red mark).
_COLOR_DARK = "#c8102e"
_COLOR_LIGHT = "#c8102e"


def _build_config() -> ContractConfig:
    return ContractConfig(
        type=CONTRACT_TYPE,
        label={
            SupportedLanguage.en: "Stratus Red Team",
            SupportedLanguage.fr: "Stratus Red Team",
        },
        color_dark=_COLOR_DARK,
        color_light=_COLOR_LIGHT,
        expose=True,
    )


def _credential_element(cred: CredField) -> ContractElement:
    if cred.textarea:
        return ContractTextArea(
            key=cred.key,
            label=cred.label,
            mandatory=cred.mandatory,
        )
    return ContractText(
        key=cred.key,
        label=cred.label,
        mandatory=cred.mandatory,
    )


def _expectations_element() -> ContractExpectations:
    return ContractExpectations(
        key="expectations",
        label="Expectations",
        mandatory=False,
        cardinality=ContractCardinality.Multiple,
        predefinedExpectations=[
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
            Expectation(
                expectation_type=ExpectationType.prevention,
                expectation_name="Prevention",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
        ],
    )


def _output_element(platform_key: str) -> ContractOutputElement:
    return ContractOutputElement(
        type=ContractOutputType.Text,
        field="technique",
        isMultiple=False,
        isFindingCompatible=False,
        labels=[platform_key, "stratus", "technique"],
    )


def _build_platform_contract(
    platform: PlatformSpec, config: ContractConfig
) -> Contract:
    technique = ContractSelect(
        key=TECHNIQUE_FIELD_KEY,
        label="Stratus technique",
        defaultValue=[next(iter(platform.techniques))],
        mandatory=True,
        choices=platform.techniques,
    )
    custom_technique = ContractText(
        key=CUSTOM_TECHNIQUE_FIELD_KEY,
        label="Custom Stratus technique id (overrides the selection above)",
        mandatory=False,
    )

    elements: List[ContractElement] = [
        _credential_element(cred) for cred in platform.cred_fields
    ]
    elements.extend([technique, custom_technique, _expectations_element()])

    fields = ContractBuilder().add_fields(elements).build_fields()

    return Contract(
        contract_id=platform.contract_id,
        config=config,
        label={
            SupportedLanguage.en: f"{platform.label_en} - Detonate Stratus technique",
            SupportedLanguage.fr: f"{platform.label_fr} - Detoner une technique Stratus",
        },
        fields=fields,
        outputs=ContractBuilder()
        .add_outputs([_output_element(platform.key)])
        .build_outputs(),
        manual=False,
        domains=[SecurityDomains.CLOUD.value],
    )


def build_all_contracts():
    """Build the detonation contract for every supported Stratus platform."""
    config = _build_config()
    contracts = [_build_platform_contract(p, config) for p in PLATFORMS]
    return prepare_contracts(contracts)
