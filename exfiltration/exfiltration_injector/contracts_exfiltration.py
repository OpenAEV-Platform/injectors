from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractExpectations,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_exfiltration"

DNS_EXFIL_CONTRACT = "d4a5b6c7-7b88-4d95-8ca3-8f9a0b1c2d34"
HTTPS_EXFIL_CONTRACT = "d4a5b6c7-7b88-4d95-8ca3-8f9a0b1c2d35"
CLOUD_EXFIL_CONTRACT = "d4a5b6c7-7b88-4d95-8ca3-8f9a0b1c2d36"

SIZE_CHOICES = {
    "1": "1 KB",
    "64": "64 KB",
    "256": "256 KB",
    "1024": "1 MB",
}


def _expectations() -> ContractExpectations:
    return ContractExpectations(
        key="expectations",
        label="Expectations",
        mandatory=False,
        cardinality=ContractCardinality.Multiple,
        predefinedExpectations=[
            Expectation(
                expectation_type=ExpectationType.prevention,
                expectation_name="Prevention",
                expectation_description="Egress / DLP control blocks the transfer.",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="The transfer is detected.",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
        ],
    )


def _size_field() -> ContractSelect:
    return ContractSelect(
        key="size_kb",
        label="Payload size",
        defaultValue=["64"],
        mandatory=True,
        choices=SIZE_CHOICES,
    )


class ExfiltrationContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Data Exfiltration",
                SupportedLanguage.fr: "Exfiltration de données",
            },
            color_dark="#9933cc",
            color_light="#9933cc",
            expose=True,
        )

        dns_domain = ContractText(
            key="dns_domain",
            label="Controlled DNS domain (e.g. exfil.example.com)",
            mandatory=True,
        )
        https_url = ContractText(
            key="https_url",
            label="Controlled HTTPS endpoint URL",
            mandatory=True,
        )
        cloud_url = ContractText(
            key="cloud_url",
            label="Cloud storage upload URL (e.g. presigned S3 URL)",
            mandatory=True,
        )

        dns_contract = Contract(
            contract_id=DNS_EXFIL_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Exfiltration - DNS tunneling",
                SupportedLanguage.fr: "Exfiltration - Tunnel DNS",
            },
            fields=ContractBuilder()
            .add_fields([dns_domain, _size_field(), _expectations()])
            .build_fields(),
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.DATA_EXFILTRATION.value],
        )

        https_contract = Contract(
            contract_id=HTTPS_EXFIL_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Exfiltration - HTTPS upload",
                SupportedLanguage.fr: "Exfiltration - Envoi HTTPS",
            },
            fields=ContractBuilder()
            .add_fields([https_url, _size_field(), _expectations()])
            .build_fields(),
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.DATA_EXFILTRATION.value],
        )

        cloud_contract = Contract(
            contract_id=CLOUD_EXFIL_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Exfiltration - Cloud storage upload",
                SupportedLanguage.fr: "Exfiltration - Envoi vers stockage cloud",
            },
            fields=ContractBuilder()
            .add_fields([cloud_url, _size_field(), _expectations()])
            .build_fields(),
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.DATA_EXFILTRATION.value],
        )

        return prepare_contracts([dns_contract, https_contract, cloud_contract])
