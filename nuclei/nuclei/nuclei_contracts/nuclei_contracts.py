import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
    ContractCardinality,
    ContractConfig,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.helpers import OpenAEVInjectorHelper

from nuclei.nuclei_contracts.nuclei_constants import (
    ASSET_GROUPS_KEY,
    ASSETS_KEY,
    CONTRACT_LABELS,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
    TYPE,
)


@dataclass
class TargetExtractionResult:
    targets: List[str]
    ip_to_asset_id_map: Dict[str, str]


class TargetProperty(Enum):
    AUTOMATIC = "Automatic"
    HOSTNAME = "Hostname"
    SEEN_IP = "Seen IP"
    LOCAL_IP = "Local IP (first)"


target_property_choices_dict = {
    property.name.lower(): property.value for property in TargetProperty
}


class NucleiContracts:

    @staticmethod
    def base_contract_config():
        return ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nuclei Scan",
                SupportedLanguage.fr: "Nuclei Scan",
            },
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

    @staticmethod
    def core_contract_fields():
        # -- FIELDS --
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
            key=ASSETS_KEY,
            label="Targeted assets",
            mandatory=False,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "assets"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "assets"},
        )
        target_asset_groups = ContractAssetGroup(
            cardinality=ContractCardinality.Multiple,
            key=ASSET_GROUPS_KEY,
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

    @staticmethod
    def core_outputs():
        output_vulns = ContractOutputElement(
            type=ContractOutputType.CVE,
            field="cve",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        output_others = ContractOutputElement(
            type=ContractOutputType.Text,
            field="others",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        return [output_vulns, output_others]

    @staticmethod
    def build_contract(
        contract_id,
        external_id,
        contract_config,
        contract_fields,
        contract_outputs,
        label_en,
        label_fr,
    ):
        return Contract(
            contract_id=contract_id,
            external_id=external_id,
            config=contract_config,
            label={
                SupportedLanguage.en: label_en,
                SupportedLanguage.fr: label_fr,
            },
            fields=ContractBuilder().add_fields(contract_fields).build_fields(),
            outputs=ContractBuilder().add_outputs(contract_outputs).build_outputs(),
            manual=False,
        )

    @staticmethod
    def build_static_contracts():
        return prepare_contracts(
            [
                NucleiContracts.build_contract(
                    cid,
                    None,
                    NucleiContracts.base_contract_config(),
                    NucleiContracts.core_contract_fields()
                    + [
                        ContractText(
                            key="template",
                            label="Manual template path (-t)",
                            mandatory=False,
                        )
                    ],
                    NucleiContracts.core_outputs(),
                    f"Nuclei - {en}",
                    f"Nuclei - {fr}",
                )
                for cid, (en, fr) in CONTRACT_LABELS.items()
            ]
        )

    @staticmethod
    def extract_targets(
        data: Dict, helper: OpenAEVInjectorHelper
    ) -> TargetExtractionResult:
        targets = []
        ip_to_asset_id_map = {}
        content = data["injection"]["inject_content"]
        if content[TARGET_SELECTOR_KEY] == "assets" and data.get(ASSETS_KEY):
            selector = content[TARGET_PROPERTY_SELECTOR_KEY]
            for asset in data[ASSETS_KEY]:
                if selector == "automatic":
                    result = NucleiContracts.extract_property_target_value(asset)
                    if result:
                        target, asset_id = result
                        targets.append(target)
                        ip_to_asset_id_map[target] = asset_id
                    else:
                        helper.injector_logger.warning(
                            f"No valid target found for asset_id={asset.get('asset_id')} "
                            f"(hostname={asset.get('endpoint_hostname')}, ips={asset.get('endpoint_ips')})"
                        )
                else:
                    if selector == "seen_ip":
                        ip_to_asset_id_map[asset["endpoint_seen_ip"]] = asset[
                            "asset_id"
                        ]
                        targets.append(asset["endpoint_seen_ip"])
                    elif selector == "local_ip":
                        if not asset["endpoint_ips"]:
                            raise ValueError("No IP found for this endpoint")
                        ip_to_asset_id_map[asset["endpoint_ips"][0]] = asset["asset_id"]
                        targets.append(asset["endpoint_ips"][0])
                    else:
                        ip_to_asset_id_map[asset["endpoint_hostname"]] = asset[
                            "asset_id"
                        ]
                        targets.append(asset["endpoint_hostname"])

        elif content[TARGET_SELECTOR_KEY] == "manual":
            targets = [t.strip() for t in content[TARGETS_KEY].split(",") if t.strip()]

        else:
            raise ValueError("No targets provided for this injection")

        return TargetExtractionResult(
            targets=targets, ip_to_asset_id_map=ip_to_asset_id_map
        )

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Filter out loopback, unspecified"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (
                ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local
            )
        except ValueError:
            return False

    @staticmethod
    def extract_property_target_value(asset: Dict) -> Optional[Tuple[str, str]]:
        """
        Extract target value from asset based on conditions:
        - Agentless + hostname => hostname
        - Otherwise => first valid IP
        """
        asset_id = asset.get("asset_id")
        agents = asset.get("asset_agents", [])
        hostname = asset.get("endpoint_hostname")
        endpoint_ips = asset.get("endpoint_ips", [])

        # Case 1: Agentless + hostname
        if not agents and hostname:
            return hostname, asset_id

        # Case 2: Agent present => try IPs
        for ip in endpoint_ips:
            if NucleiContracts.is_valid_ip(ip):
                return ip, asset_id

        return None
