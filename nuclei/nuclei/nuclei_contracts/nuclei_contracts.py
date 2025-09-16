from dataclasses import dataclass
from typing import Dict, List, Tuple

from pyobas.contracts import ContractBuilder
from pyobas.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractCardinality,
    ContractConfig,
    ContractElement,
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

from nuclei.nuclei_contracts.nuclei_constants import (
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


class NucleiContracts:

    @staticmethod
    def build_contracts():
        # -- CONFIG --
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nuclei Scan",
                SupportedLanguage.fr: "Nuclei Scan",
            },
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

        # -- FIELDS --
        target_selector = ContractSelect(
            key=TARGET_SELECTOR_KEY,
            label="Type of targets",
            defaultValue=["assets"],
            mandatory=True,
            choices={"assets": "Assets", "manual": "Manual"},
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
        target_property_selector = ContractSelect(
            key=TARGET_PROPERTY_SELECTOR_KEY,
            label="Targeted assets property",
            defaultValue=["automatic"],
            mandatory=False,
            choices={
                "automatic": "Automatic",
                "hostname": "Hostname",
                "seen_ip": "Seen IP",
                "local_ip": "Local IP (first)",
            },
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "assets"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "assets"},
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
        template_manual = ContractText(
            key="template",
            label="Manual template path (-t)",
            mandatory=False,
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

        # -- OUTPUTS --
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

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    target_selector,
                    targets_assets,
                    target_property_selector,
                    targets_manual,
                    template_manual,
                    expectations,
                ]
            )
            .build_fields()
        )
        nuclei_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder().add_outputs([output_vulns, output_others]).build_outputs()
        )

        def build_contract(contract_id, label_en, label_fr):
            return Contract(
                contract_id=contract_id,
                config=contract_config,
                label={
                    SupportedLanguage.en: label_en,
                    SupportedLanguage.fr: label_fr,
                },
                fields=fields,
                outputs=nuclei_contract_outputs,
                manual=False,
            )

        return prepare_contracts(
            [
                build_contract(cid, f"Nuclei - {en}", f"Nuclei - {fr}")
                for cid, (en, fr) in CONTRACT_LABELS.items()
            ]
        )

    @staticmethod
    def extract_targets(data: Dict) -> TargetExtractionResult:
        targets = []
        ip_to_asset_id_map = {}
        content = data["injection"]["inject_content"]

        if content[TARGET_SELECTOR_KEY] == "assets" and data.get(ASSETS_KEY):
            selector = content[TARGET_PROPERTY_SELECTOR_KEY]
            if selector == "automatic":
                for asset in data[ASSETS_KEY]:
                    target, asset_id = NucleiContracts.extract_property_target_value(asset)
                    targets.append(target)
                    ip_to_asset_id_map[target] = asset_id
            else:
                for asset in data[ASSETS_KEY]:
                    if selector == "seen_ip":
                        ip_to_asset_id_map[asset["endpoint_seen_ip"]] = asset["asset_id"]
                        targets.append(asset["endpoint_seen_ip"])
                    elif selector == "local_ip":
                        if not asset["endpoint_ips"]:
                            raise ValueError("No IP found for this endpoint")
                        ip_to_asset_id_map[asset["endpoint_ips"][0]] = asset["asset_id"]
                        targets.append(asset["endpoint_ips"][0])
                    else:
                        ip_to_asset_id_map[asset["endpoint_hostname"]] = asset["asset_id"]
                        targets.append(asset["endpoint_hostname"])

        elif content[TARGET_SELECTOR_KEY] == "manual":
            targets = [t.strip() for t in content[TARGETS_KEY].split(",") if t.strip()]

        else:
            raise ValueError("No targets provided for this injection")

        return TargetExtractionResult(targets=targets, ip_to_asset_id_map=ip_to_asset_id_map)

    @staticmethod
    def extract_property_target_value(asset: Dict) -> Tuple[str, str]:
        """
        Extracts the target value from an asset based on priority:
        1. endpoint_hostname
        2. endpoint_seen_ip
        3. first of endpoint_ips
        """
        if asset.get("endpoint_hostname"):
            return asset["endpoint_hostname"], asset["asset_id"]

        if asset.get("endpoint_seen_ip"):
            return asset["endpoint_seen_ip"], asset["asset_id"]

        if asset.get("endpoint_ips"):
            if not asset["endpoint_ips"]:
                raise ValueError(f"Asset {asset['asset_id']} has empty endpoint_ips list")
            return asset["endpoint_ips"][0], asset["asset_id"]

        raise ValueError(f"No valid target property found for asset {asset['asset_id']}")
