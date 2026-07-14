from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_censys"

HOST_SEARCH_CONTRACT = "9c5d4e7f-3d44-4f51-8e60-4b5c6d7e8f90"
CERT_SEARCH_CONTRACT = "9c5d4e7f-3d44-4f51-8e60-4b5c6d7e8f91"


class CensysContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Censys",
                SupportedLanguage.fr: "Censys",
            },
            color_dark="#0b3d91",
            color_light="#0b3d91",
            expose=True,
        )

        query = ContractText(
            key="query",
            label="Censys search query",
            mandatory=True,
        )

        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.vulnerability,
                    expectation_name="Vulnerability",
                    expectation_description="",
                    expectation_score=100,
                    expectation_expectation_group=False,
                )
            ],
        )

        output_hosts = ContractOutputElement(
            type=ContractOutputType.IPv4,
            field="hosts",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["censys", "host"],
        )
        output_ports = ContractOutputElement(
            type=ContractOutputType.Port,
            field="ports",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["censys", "port"],
        )
        output_certificates = ContractOutputElement(
            type=ContractOutputType.Text,
            field="certificates",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["censys", "certificate"],
        )

        base_fields = ContractBuilder().add_fields([query, expectations]).build_fields()

        host_contract = Contract(
            contract_id=HOST_SEARCH_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Censys - Host search",
                SupportedLanguage.fr: "Censys - Recherche d'hôtes",
            },
            fields=base_fields,
            outputs=ContractBuilder()
            .add_outputs([output_hosts, output_ports])
            .build_outputs(),
            manual=False,
            domains=[SecurityDomains.NETWORK.value],
        )

        cert_contract = Contract(
            contract_id=CERT_SEARCH_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Censys - Certificate search",
                SupportedLanguage.fr: "Censys - Recherche de certificats",
            },
            fields=base_fields,
            outputs=ContractBuilder()
            .add_outputs([output_certificates])
            .build_outputs(),
            manual=False,
            domains=[SecurityDomains.NETWORK.value],
        )

        return prepare_contracts([host_contract, cert_contract])
