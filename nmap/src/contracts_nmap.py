from typing import List


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

from constants_nmap import (
    TARGET_SELECTOR_KEY,
    ASSETS_KEY,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGETS_KEY,
)

TYPE = "openbas_nmap"
TCP_SYN_SCAN_CONTRACT = "0b7f3674-ac5d-4b95-b749-6665e74a211f"
TCP_CONNECT_SCAN_CONTRACT = "93d27459-68d0-43b1-ad65-eacc3cfa5cf7"
FIN_SCAN_CONTRACT = "6f4d7e18-c730-484a-bb09-c9c321820c0a"


class NmapContracts:

    @staticmethod
    def build_contract():
        # -- CONFIG --
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nmap Scan",
                SupportedLanguage.fr: "Nmap Scan",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
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
            defaultValue=["seen_ip"],
            choices={
                "seen_ip": "Seen IP",
                "local_ip": "Local IP (first)",
                "hostname": "Hostname",
            },
            mandatory=False,
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
        expectations = ContractExpectations(
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
                )
            ],
        )

        # -- OUTPUTS --
        output_ports_scans = ContractOutputElement(
            type=ContractOutputType.PortsScan,
            field="scan_results",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["scan"],
        )
        output_port = ContractOutputElement(
            type=ContractOutputType.Port,
            field="ports",
            isMultiple=True,
            isFindingCompatible=False,
            labels=["scan"],
        )
        # Post contract raw
        nmap_contract_fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    target_selector,
                    targets_assets,
                    target_property_selector,
                    targets_manual,
                    expectations,
                ]
            )
            .build_fields()
        )
        nmap_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder()
            .add_outputs([output_ports_scans, output_port])
            .build_outputs()
        )
        syn_scan_contract = Contract(
            contract_id=TCP_SYN_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - SYN Scan",
                SupportedLanguage.fr: "Nmap - SYN Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        tcp_scan_contract = Contract(
            contract_id=TCP_CONNECT_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - TCP Connect Scan",
                SupportedLanguage.fr: "Nmap - TCP Connect Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        fin_scan_contract = Contract(
            contract_id=FIN_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - FIN Scan",
                SupportedLanguage.fr: "Nmap - FIN Scan",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
        )
        return prepare_contracts(
            [syn_scan_contract, tcp_scan_contract, fin_scan_contract]
        )
