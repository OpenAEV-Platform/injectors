from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
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
    SecurityPlatformType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

from injector_common.constants import (
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.scan_budget import SCAN_TIMEOUT_FIELD
from injector_common.targets import TargetProperty, target_property_choices_dict
from nmap.contracts.nmap_constants import (
    FIN_SCAN_CONTRACT,
    HOST_TIMEOUT_KEY,
    MAX_RETRIES_KEY,
    MAX_RTT_TIMEOUT_KEY,
    MIN_RATE_KEY,
    PORTS_KEY,
    TCP_CONNECT_SCAN_CONTRACT,
    TCP_SYN_SCAN_CONTRACT,
    TCP_SYN_VERSION_SCAN_CONTRACT,
    TIMING_DEFAULT,
    TIMING_KEY,
    TIMING_TEMPLATES,
    TOP_PORTS_KEY,
    TYPE,
)

_TIMING_LABELS = {
    "T0": "T0 paranoid",
    "T1": "T1 sneaky",
    "T2": "T2 polite",
    "T3": "T3 normal",
    "T4": "T4 aggressive",
    "T5": "T5 insane",
}


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
            choices=target_property_choices_dict,
            mandatory=False,
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

        # -- TUNING (optional; an empty field keeps nmap's default, except the host
        # timeout and the retries, which get the injector's safe defaults) --
        timing = ContractSelect(
            key=TIMING_KEY,
            label="Timing template",
            defaultValue=[TIMING_DEFAULT],
            mandatory=False,
            choices={
                TIMING_DEFAULT: "nmap default (T3)",
                **{t: _TIMING_LABELS[t] for t in TIMING_TEMPLATES},
            },
        )
        max_retries = ContractText(
            key=MAX_RETRIES_KEY,
            label=(
                "Max retries per port (--max-retries, empty = injector default, "
                "2 unless the deployment sets NMAP_DEFAULT_MAX_RETRIES)"
            ),
            mandatory=False,
        )
        host_timeout = ContractText(
            key=HOST_TIMEOUT_KEY,
            label=(
                "Give up on a host after (seconds, --host-timeout, empty = injector "
                "default, 300 unless the deployment sets "
                "NMAP_DEFAULT_HOST_TIMEOUT_SECONDS; 0 = no limit)"
            ),
            mandatory=False,
        )
        max_rtt_timeout = ContractText(
            key=MAX_RTT_TIMEOUT_KEY,
            label="Max probe round trip (milliseconds, --max-rtt-timeout)",
            mandatory=False,
        )
        min_rate = ContractText(
            key=MIN_RATE_KEY,
            label="Min packets per second (--min-rate)",
            mandatory=False,
        )
        top_ports = ContractText(
            key=TOP_PORTS_KEY,
            label="Scan the N most common ports (--top-ports, empty = nmap default 1,000)",
            mandatory=False,
        )
        ports = ContractText(
            key=PORTS_KEY,
            label="Ports to scan (-p, e.g. 22,80,443,8000-8100; instead of top ports)",
            mandatory=False,
        )
        # Whole-run ceiling (seconds). Empty: the deployment value
        # (NMAP_SCAN_TIMEOUT), else derived from the platform inject execution
        # threshold. On expiry the hosts already scanned are kept.
        scan_timeout = ContractText(
            key=SCAN_TIMEOUT_FIELD,
            label="Scan time limit in seconds (empty: deployment default)",
            mandatory=False,
        )

        expectation_items = [
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
                expectation_expected_security_platform_types=[
                    SecurityPlatformType.NDR,
                    SecurityPlatformType.SIEM,
                    SecurityPlatformType.XDR,
                ],
            ),
            Expectation(
                expectation_type=ExpectationType.prevention,
                expectation_name="Prevention",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
                expectation_expected_security_platform_types=[
                    SecurityPlatformType.NDR,
                    SecurityPlatformType.XDR,
                ],
            ),
        ]
        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            availableExpectations=expectation_items,
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
        # The raw nmap XML report, stored as a single non-finding-compatible entry:
        # it never shows up as a visible Finding, but stays usable as a
        # chaining/event filter, independent of the structured PortsScan/Port
        # extraction above.
        output_action_output = ContractOutputElement(
            type=ContractOutputType.ActionOutput,
            field="action_output",
            isMultiple=False,
            isFindingCompatible=False,
            labels=["scan"],
        )
        expectation_signatures = ContractOutputElement(
            type=ContractOutputType.ExpectationSignature,
            field="expectation_signatures",
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
                    target_asset_groups,
                    target_property_selector,
                    targets_manual,
                    timing,
                    max_retries,
                    host_timeout,
                    max_rtt_timeout,
                    min_rate,
                    top_ports,
                    ports,
                    scan_timeout,
                    expectations,
                ]
            )
            .build_fields()
        )
        nmap_contract_outputs: List[ContractOutputElement] = (
            ContractBuilder()
            .add_outputs(
                [
                    output_ports_scans,
                    output_port,
                    output_action_output,
                    expectation_signatures,
                ]
            )
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
            domains=[SecurityDomains.NETWORK.value],
            contract_attack_patterns_external_ids=["T1046"],
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
            domains=[SecurityDomains.NETWORK.value],
            contract_attack_patterns_external_ids=["T1046"],
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
            domains=[SecurityDomains.NETWORK.value],
            contract_attack_patterns_external_ids=["T1046"],
        )
        # SYN scan plus service/version detection (-sV): slower, but the service of
        # each open port is probed instead of guessed from nmap's port table.
        syn_version_scan_contract = Contract(
            contract_id=TCP_SYN_VERSION_SCAN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Nmap - SYN Scan with service/version detection",
                SupportedLanguage.fr: "Nmap - SYN Scan avec détection de version",
            },
            fields=nmap_contract_fields,
            outputs=nmap_contract_outputs,
            manual=False,
            domains=[SecurityDomains.NETWORK.value],
            contract_attack_patterns_external_ids=["T1046"],
        )
        return prepare_contracts(
            [
                syn_scan_contract,
                tcp_scan_contract,
                fin_scan_contract,
                syn_version_scan_contract,
            ]
        )
