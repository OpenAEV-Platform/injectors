from dataclasses import dataclass
from typing import Dict, List

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
            defaultValue=["assets"],
            mandatory=True,
            mandatoryGroups=["assets", "targets"],
            choices={"assets": "Assets", "manual": "Manual"},
        )
        targets_assets = ContractAsset(
            cardinality=ContractCardinality.Multiple,
            key=ASSETS_KEY,
            label="Targeted assets",
            mandatory=False,
        )
        target_property_selector = ContractSelect(
            key=TARGET_PROPERTY_SELECTOR_KEY,
            label="Targeted property",
            defaultValue=["hostname"],
            mandatory=False,
            choices={
                "hostname": "Hostname",
                "seen_ip": "Seen IP",
                "local_ip": "Local IP (first)",
            },
        )
        targets_manual = ContractText(
            key=TARGETS_KEY,
            label="Manual targets (comma-separated)",
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

        return [
            target_selector,
            targets_assets,
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
    def extract_targets(data: Dict) -> TargetExtractionResult:
        targets = []
        ip_to_asset_id_map = {}
        content = data["injection"]["inject_content"]
        if content[TARGET_SELECTOR_KEY] == "assets" and data.get(ASSETS_KEY):
            selector = content[TARGET_PROPERTY_SELECTOR_KEY]
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
        return TargetExtractionResult(
            targets=targets, ip_to_asset_id_map=ip_to_asset_id_map
        )
