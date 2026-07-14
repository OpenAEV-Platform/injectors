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

TYPE = "openaev_webapp"

ZAP_BASELINE_CONTRACT = "e5b6c7d8-8c99-4ea6-8db4-9a0b1c2d3e45"
SQLMAP_CONTRACT = "e5b6c7d8-8c99-4ea6-8db4-9a0b1c2d3e46"


def _expectations() -> ContractExpectations:
    return ContractExpectations(
        key="expectations",
        label="Expectations",
        mandatory=False,
        cardinality=ContractCardinality.Multiple,
        predefinedExpectations=[
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="The WAF / monitoring detects the attack.",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
            Expectation(
                expectation_type=ExpectationType.vulnerability,
                expectation_name="Vulnerability",
                expectation_description="The application is vulnerable.",
                expectation_score=100,
                expectation_expectation_group=False,
            ),
        ],
    )


class WebappContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Web Application Attack",
                SupportedLanguage.fr: "Attaque d'application web",
            },
            color_dark="#ff9933",
            color_light="#ff9933",
            expose=True,
        )

        target_url = ContractText(
            key="target_url",
            label="Target URL",
            mandatory=True,
        )

        output_vulnerabilities = ContractOutputElement(
            type=ContractOutputType.Vulnerability,
            field="vulnerabilities",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["webapp", "vulnerability"],
        )

        zap_contract = Contract(
            contract_id=ZAP_BASELINE_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Web App - OWASP ZAP baseline scan",
                SupportedLanguage.fr: "Web App - Scan de base OWASP ZAP",
            },
            fields=ContractBuilder()
            .add_fields([target_url, _expectations()])
            .build_fields(),
            outputs=ContractBuilder()
            .add_outputs([output_vulnerabilities])
            .build_outputs(),
            manual=False,
            domains=[SecurityDomains.WEB_APP.value],
        )

        sqlmap_contract = Contract(
            contract_id=SQLMAP_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Web App - SQLMap injection test",
                SupportedLanguage.fr: "Web App - Test d'injection SQLMap",
            },
            fields=ContractBuilder()
            .add_fields([target_url, _expectations()])
            .build_fields(),
            outputs=ContractBuilder()
            .add_outputs([output_vulnerabilities])
            .build_outputs(),
            manual=False,
            domains=[SecurityDomains.WEB_APP.value],
        )

        return prepare_contracts([zap_contract, sqlmap_contract])
