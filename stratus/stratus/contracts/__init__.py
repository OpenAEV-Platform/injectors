"""Stratus Red Team contracts package.

The injector exposes one contract per Stratus technique (fixed technique, tagged
with its MITRE ATT&CK patterns) plus one "custom technique" contract per
platform for detonating any technique id in the pinned Stratus release.

Public API:
- ``build_all_contracts()``: every contract, ready for injector registration.
- ``CONTRACT_REGISTRY``: maps a contract id to its :class:`ResolvedContract`
  (platform + fixed technique id, or ``None`` for the custom contracts) so the
  injector can resolve credentials and the technique at detonation time.
- ``technique_contract_id()``: deterministic, stable id for a technique contract.
"""

import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
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
    PLATFORMS_BY_KEY,
    CredField,
    PlatformSpec,
)
from stratus.contracts.techniques import TECHNIQUES, Technique

CONTRACT_TYPE = "openaev_stratus"

# Free-form technique id field used only by the per-platform custom contracts.
CUSTOM_TECHNIQUE_FIELD_KEY = "technique_id"

# Stratus Red Team brand colors (navy badge / red mark).
_COLOR_DARK = "#c8102e"
_COLOR_LIGHT = "#c8102e"

# Fixed namespace so a technique id always maps to the same contract id.
_CONTRACT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "openaev-stratus")


def technique_contract_id(technique_id: str) -> str:
    """Deterministic, stable contract id for a fixed-technique contract."""
    return str(uuid.uuid5(_CONTRACT_NAMESPACE, technique_id))


@dataclass(frozen=True)
class ResolvedContract:
    """How a contract id maps back to a platform and (optional) fixed technique."""

    platform: PlatformSpec
    # None for the per-platform custom contracts, where the technique id is read
    # from the inject content instead.
    technique_id: Optional[str]


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
            key=cred.key, label=cred.label, mandatory=cred.mandatory
        )
    return ContractText(key=cred.key, label=cred.label, mandatory=cred.mandatory)


def _expectations_element() -> ContractExpectations:
    expectation_items = [
        Expectation(
            expectation_type=ExpectationType.detection,
            expectation_name="Detection",
            expectation_description="",
            expectation_score=100,
            expectation_expectation_group=False,
            expectation_is_predefined=True,
        ),
        Expectation(
            expectation_type=ExpectationType.prevention,
            expectation_name="Prevention",
            expectation_description="",
            expectation_score=100,
            expectation_expectation_group=False,
            expectation_is_predefined=True,
        ),
    ]
    return ContractExpectations(
        key="expectations",
        label="Expectations",
        mandatory=False,
        cardinality=ContractCardinality.Multiple,
        availableExpectations=expectation_items,
    )


def _output_element(platform_key: str) -> ContractOutputElement:
    return ContractOutputElement(
        type=ContractOutputType.Text,
        field="technique",
        isMultiple=False,
        isFindingCompatible=False,
        labels=[platform_key, "stratus", "technique"],
    )


def _make_contract(
    contract_id: str,
    label_en: str,
    label_fr: str,
    platform: PlatformSpec,
    extra_fields: List[ContractElement],
    attack_patterns: List[str],
) -> Contract:
    elements: List[ContractElement] = [
        _credential_element(cred) for cred in platform.cred_fields
    ]
    elements.extend(extra_fields)
    elements.append(_expectations_element())

    return Contract(
        contract_id=contract_id,
        config=_CONFIG,
        label={SupportedLanguage.en: label_en, SupportedLanguage.fr: label_fr},
        fields=ContractBuilder().add_fields(elements).build_fields(),
        outputs=ContractBuilder()
        .add_outputs([_output_element(platform.key)])
        .build_outputs(),
        manual=False,
        contract_attack_patterns_external_ids=list(attack_patterns),
        domains=[SecurityDomains.CLOUD.value],
    )


def _technique_contract(technique: Technique) -> Contract:
    platform = PLATFORMS_BY_KEY[technique.platform]
    label = f"{platform.label} - {technique.name}"
    return _make_contract(
        contract_id=technique_contract_id(technique.id),
        label_en=label,
        label_fr=label,
        platform=platform,
        extra_fields=[],
        attack_patterns=list(technique.attack_patterns),
    )


def _custom_contract(platform: PlatformSpec) -> Contract:
    technique_field = ContractText(
        key=CUSTOM_TECHNIQUE_FIELD_KEY,
        label="Stratus technique id (e.g. aws.persistence.iam-backdoor-user)",
        mandatory=True,
    )
    label = f"{platform.label} - Detonate a custom Stratus technique"
    return _make_contract(
        contract_id=platform.custom_contract_id,
        label_en=label,
        label_fr=label,
        platform=platform,
        extra_fields=[technique_field],
        attack_patterns=[],
    )


# Single shared contract config instance across every contract.
_CONFIG = _build_config()


def _build_registry() -> Dict[str, ResolvedContract]:
    registry: Dict[str, ResolvedContract] = {}
    for technique in TECHNIQUES:
        platform = PLATFORMS_BY_KEY[technique.platform]
        registry[technique_contract_id(technique.id)] = ResolvedContract(
            platform=platform, technique_id=technique.id
        )
    for platform in PLATFORMS:
        registry[platform.custom_contract_id] = ResolvedContract(
            platform=platform, technique_id=None
        )
    return registry


CONTRACT_REGISTRY: Dict[str, ResolvedContract] = _build_registry()


def build_all_contracts():
    """Build every Stratus contract: one per technique plus per-platform custom."""
    contracts: List[Contract] = [_technique_contract(t) for t in TECHNIQUES]
    contracts.extend(_custom_contract(p) for p in PLATFORMS)
    return prepare_contracts(contracts)
