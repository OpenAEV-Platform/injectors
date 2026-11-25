from typing import List

from dns_enum.contracts.dns_enum_constants import (
    ACTION_OUTPUT_FIELD,
    ASSET_GROUP_ID_KEY,
    BRUTE_FORCE_KEY,
    CLASSIFY_ASSETS_KEY,
    CREATE_ENDPOINTS_KEY,
    DEFAULT_ENDPOINT_TAG,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RECORD_TYPES,
    DEFAULT_TIMEOUT_SECONDS,
    DISCOVERED_HOSTS_FIELD,
    DNS_ENUMERATION_CONTRACT,
    DOMAINS_KEY,
    ENDPOINT_TAG_KEY,
    EXPECTATION_SIGNATURES_FIELD,
    HOSTNAMES_FIELD,
    IPV4_FIELD,
    MANUAL_TARGETS_FIELD,
    PASSIVE_SOURCES_KEY,
    RATE_LIMIT_KEY,
    RECORD_TYPES,
    RECORD_TYPES_KEY,
    TIMEOUT_KEY,
    TYPE,
    WORDLIST_KEY,
)
from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAssetGroupReference,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractTags,
    ContractText,
    ContractTextArea,
    Expectation,
    ExpectationType,
    SecurityPlatformType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains


class DnsEnumContracts:

    @staticmethod
    def build_fields() -> List[ContractElement]:
        domains = ContractText(
            key=DOMAINS_KEY,
            label="Root domains (comma-separated)",
            mandatory=True,
        )
        passive_sources = ContractCheckbox(
            key=PASSIVE_SOURCES_KEY,
            label="Enumerate subdomains from passive sources (subfinder)",
            defaultValue=True,
        )
        record_types = ContractSelect(
            key=RECORD_TYPES_KEY,
            label="DNS record types to resolve (dnsx)",
            cardinality=ContractCardinality.Multiple,
            defaultValue=list(DEFAULT_RECORD_TYPES),
            mandatory=True,
            choices={record_type: record_type for record_type in RECORD_TYPES},
        )
        brute_force = ContractCheckbox(
            key=BRUTE_FORCE_KEY,
            label="Brute force subdomains with a wordlist",
            defaultValue=False,
        )
        wordlist = ContractTextArea(
            key=WORDLIST_KEY,
            label="Wordlist (one subdomain label per line)",
            mandatory=False,
            mandatoryConditionFields=[BRUTE_FORCE_KEY],
            mandatoryConditionValues={BRUTE_FORCE_KEY: True},
            visibleConditionFields=[BRUTE_FORCE_KEY],
            visibleConditionValues={BRUTE_FORCE_KEY: True},
        )
        rate_limit = ContractText(
            key=RATE_LIMIT_KEY,
            label="Rate limit (DNS queries per second)",
            defaultValue=str(DEFAULT_RATE_LIMIT),
            mandatory=False,
        )
        timeout = ContractText(
            key=TIMEOUT_KEY,
            label="Timeout (seconds)",
            defaultValue=str(DEFAULT_TIMEOUT_SECONDS),
            mandatory=False,
        )
        create_endpoints = ContractCheckbox(
            key=CREATE_ENDPOINTS_KEY,
            label="Create endpoints for discovered hosts",
            defaultValue=False,
        )
        # Tag picker: the inject content holds tag ids. An inject saved before the
        # picker holds tag names (comma-separated text); the injector accepts both.
        endpoint_tag = ContractTags(
            key=ENDPOINT_TAG_KEY,
            label=f"Tags set on the created endpoints (default {DEFAULT_ENDPOINT_TAG})",
            mandatory=False,
            visibleConditionFields=[CREATE_ENDPOINTS_KEY],
            visibleConditionValues={CREATE_ENDPOINTS_KEY: True},
        )
        # Asset group picker; the selected id is stored under the same key as the
        # former free-text ID field, so existing injects keep working.
        asset_group_id = ContractAssetGroupReference(
            key=ASSET_GROUP_ID_KEY,
            label="Asset group to add the created endpoints to (optional)",
            cardinality=ContractCardinality.One,
            mandatory=False,
            visibleConditionFields=[CREATE_ENDPOINTS_KEY],
            visibleConditionValues={CREATE_ENDPOINTS_KEY: True},
        )
        classify_assets = ContractCheckbox(
            key=CLASSIFY_ASSETS_KEY,
            label=(
                "Classify the endpoints (shared address or CDN: web application with"
                " its URL; else host) and attach a name to the existing asset of its"
                " address"
            ),
            defaultValue=True,
            visibleConditionFields=[CREATE_ENDPOINTS_KEY],
            visibleConditionValues={CREATE_ENDPOINTS_KEY: True},
        )
        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            availableExpectations=[
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
            ],
        )
        return (
            ContractBuilder()
            .add_fields(
                [
                    domains,
                    passive_sources,
                    record_types,
                    brute_force,
                    wordlist,
                    rate_limit,
                    timeout,
                    create_endpoints,
                    endpoint_tag,
                    asset_group_id,
                    classify_assets,
                    expectations,
                ]
            )
            .build_fields()
        )

    @staticmethod
    def build_outputs() -> List[ContractOutputElement]:
        # One Text finding per resolved hostname ("host -> records").
        discovered_hosts = ContractOutputElement(
            type=ContractOutputType.Text,
            field=DISCOVERED_HOSTS_FIELD,
            isMultiple=True,
            isFindingCompatible=True,
            labels=["dns", "subdomain"],
        )
        # Every resolved IPv4 address as an IPv4 finding.
        ipv4 = ContractOutputElement(
            type=ContractOutputType.IPv4,
            field=IPV4_FIELD,
            isMultiple=True,
            isFindingCompatible=True,
            labels=["dns", "ipv4"],
        )
        # Chaining only: the resolved hostnames, one value each.
        hostnames = ContractOutputElement(
            type=ContractOutputType.Text,
            field=HOSTNAMES_FIELD,
            isMultiple=True,
            isFindingCompatible=False,
            labels=["dns", "hostname"],
        )
        # Chaining only: the resolved hostnames comma-separated, the format of the
        # "Manual targets" field of the Nmap and Nuclei injectors.
        manual_targets = ContractOutputElement(
            type=ContractOutputType.Text,
            field=MANUAL_TARGETS_FIELD,
            isMultiple=False,
            isFindingCompatible=False,
            labels=["dns", "targets"],
        )
        action_output = ContractOutputElement(
            type=ContractOutputType.ActionOutput,
            field=ACTION_OUTPUT_FIELD,
            isMultiple=False,
            isFindingCompatible=False,
            labels=["dns"],
        )
        expectation_signatures = ContractOutputElement(
            type=ContractOutputType.ExpectationSignature,
            field=EXPECTATION_SIGNATURES_FIELD,
            isMultiple=True,
            isFindingCompatible=False,
            labels=["dns"],
        )
        return (
            ContractBuilder()
            .add_outputs(
                [
                    discovered_hosts,
                    ipv4,
                    hostnames,
                    manual_targets,
                    action_output,
                    expectation_signatures,
                ]
            )
            .build_outputs()
        )

    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "DNS Enumeration",
                SupportedLanguage.fr: "Énumération DNS",
            },
            color_dark="#00897b",
            color_light="#00897b",
            expose=True,
        )
        dns_enumeration_contract = Contract(
            contract_id=DNS_ENUMERATION_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "DNS / subdomain enumeration",
                SupportedLanguage.fr: "Énumération DNS / sous-domaines",
            },
            fields=DnsEnumContracts.build_fields(),
            outputs=DnsEnumContracts.build_outputs(),
            manual=False,
            domains=[SecurityDomains.NETWORK.value],
            # T1590.002: Gather Victim Network Information: DNS
            # T1596.001: Search Open Technical Databases: DNS/Passive DNS
            contract_attack_patterns_external_ids=["T1590.002", "T1596.001"],
        )
        return prepare_contracts([dns_enumeration_contract])
