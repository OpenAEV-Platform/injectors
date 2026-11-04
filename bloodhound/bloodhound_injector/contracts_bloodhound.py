from typing import List

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
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_bloodhound"

AD_COLLECTION_CONTRACT = "a7d8e9f0-abbb-4ac8-8fd6-bc2d3e4f5a67"


class BloodhoundContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "BloodHound AD",
                SupportedLanguage.fr: "BloodHound AD",
            },
            color_dark="#b00020",
            color_light="#b00020",
            expose=True,
        )

        domain = ContractText(key="domain", label="AD domain (FQDN)", mandatory=True)
        username = ContractText(key="username", label="Username", mandatory=True)
        password = ContractText(key="password", label="Password", mandatory=True)
        domain_controller = ContractText(
            key="domain_controller",
            label="Domain controller (host or IP)",
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
                    expectation_description="Privilege-escalation attack paths exist.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
                Expectation(
                    expectation_type=ExpectationType.detection,
                    expectation_name="Detection",
                    expectation_description="The AD enumeration is detected.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
            ],
        )

        output_users = ContractOutputElement(
            type=ContractOutputType.Username,
            field="users",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["bloodhound", "ad", "user"],
        )
        output_computers = ContractOutputElement(
            type=ContractOutputType.Computer,
            field="computers",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["bloodhound", "ad", "computer"],
        )
        output_paths = ContractOutputElement(
            type=ContractOutputType.Vulnerability,
            field="attack_paths",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["bloodhound", "ad", "attack_path"],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields([domain, username, password, domain_controller, expectations])
            .build_fields()
        )

        contract = Contract(
            contract_id=AD_COLLECTION_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "BloodHound - Collect AD attack paths",
                SupportedLanguage.fr: "BloodHound - Collecter les chemins d'attaque AD",
            },
            fields=fields,
            outputs=ContractBuilder()
            .add_outputs([output_users, output_computers, output_paths])
            .build_outputs(),
            manual=False,
            domains=[SecurityDomains.ENDPOINT.value],
        )

        return prepare_contracts([contract])
