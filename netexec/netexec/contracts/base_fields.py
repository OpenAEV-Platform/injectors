"""Factory functions for building shared contract fields across all families."""

from typing import List

from pyoaev.contracts.contract_config import (
    ContractAsset,
    ContractAssetGroup,
    ContractElement,
    ContractExpectations,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
)
from pyoaev.contracts.contract_utils import ContractCardinality

from injector_common.constants import (
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.targets import TargetProperty, target_property_choices_dict

from netexec.contracts.protocol_config import PROTOCOL_CONFIGS

# Credential field definitions keyed by their field name.
_CREDENTIAL_DEFS = {
    "username": {"label": "Username"},
    "password": {"label": "Password"},
    "hash": {"label": "NTLM hash"},
    "domain": {"label": "Domain"},
    "key_file": {"label": "SSH private key file path"},
}


def build_credential_fields(protocol: str) -> List[ContractElement]:
    """Return credential ContractText fields for *protocol*."""
    config = PROTOCOL_CONFIGS[protocol]
    fields: List[ContractElement] = []
    for cred_key in config["credentials"]:
        defn = _CREDENTIAL_DEFS[cred_key]
        fields.append(ContractText(key=cred_key, label=defn["label"], mandatory=False))
    return fields


def build_port_field(protocol: str) -> ContractText:
    """Return a port ContractText field with the protocol default."""
    config = PROTOCOL_CONFIGS[protocol]
    default = config["default_port"]
    return ContractText(
        key="port",
        label=f"Port (default: {default})",
        mandatory=False,
    )


def build_core_fields() -> List[ContractElement]:
    """Target selector, asset groups, manual targets, and expectations.

    Identical to the former ``NetExecContracts.core_contract_fields()``.
    """
    target_selector = ContractSelect(
        key=TARGET_SELECTOR_KEY,
        label="Type of targets",
        defaultValue=["asset-groups"],
        mandatory=True,
        choices={
            "assets": "Assets",
            "manual": "Manual",
            "asset-groups": "Asset groups",
        },
    )
    targets_assets = ContractAsset(
        cardinality=ContractCardinality.Multiple,
        label="Targeted assets",
        mandatory=False,
        mandatoryConditionFields=[target_selector.key],
        mandatoryConditionValues={target_selector.key: "assets"},
        visibleConditionFields=[target_selector.key],
        visibleConditionValues={target_selector.key: "assets"},
    )
    target_asset_groups = ContractAssetGroup(
        cardinality=ContractCardinality.Multiple,
        label="Targeted asset groups",
        mandatory=False,
        mandatoryConditionFields=[target_selector.key],
        mandatoryConditionValues={target_selector.key: "asset-groups"},
        visibleConditionFields=[target_selector.key],
        visibleConditionValues={target_selector.key: "asset-groups"},
    )
    target_property_selector = ContractSelect(
        key=TARGET_PROPERTY_SELECTOR_KEY,
        label="Targeted assets property",
        defaultValue=[TargetProperty.AUTOMATIC.name.lower()],
        mandatory=False,
        choices=target_property_choices_dict,
        mandatoryConditionFields=[target_selector.key],
        mandatoryConditionValues={target_selector.key: ["assets", "asset-groups"]},
        visibleConditionFields=[target_selector.key],
        visibleConditionValues={target_selector.key: ["assets", "asset-groups"]},
    )
    targets_manual = ContractText(
        key=TARGETS_KEY,
        label="Manual targets (comma-separated)",
        mandatory=False,
        mandatoryConditionFields=[target_selector.key],
        mandatoryConditionValues={target_selector.key: "manual"},
        visibleConditionFields=[target_selector.key],
        visibleConditionValues={target_selector.key: "manual"},
    )
    expectations = ContractExpectations(
        key="expectations",
        label="Expectations",
        mandatory=False,
        cardinality=ContractCardinality.Multiple,
        predefinedExpectations=[
            Expectation(
                expectation_type=ExpectationType.vulnerability,
                expectation_name="Not vulnerable",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
            )
        ],
    )

    return [
        target_selector,
        targets_assets,
        target_asset_groups,
        target_property_selector,
        targets_manual,
        expectations,
    ]


def build_protocol_base_fields(protocol: str) -> List[ContractElement]:
    """Assemble the shared fields present in **every** contract for *protocol*.

    Order: credentials -> port -> core (target selector, assets, expectations).
    """
    fields: List[ContractElement] = []
    fields.extend(build_credential_fields(protocol))
    fields.append(build_port_field(protocol))
    fields.extend(build_core_fields())
    return fields
