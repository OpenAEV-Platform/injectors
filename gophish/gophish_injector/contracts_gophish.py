from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_gophish"

GOPHISH_CAMPAIGN_CONTRACT = "b2e3f4a5-5f66-4b73-9a81-6d7e8f9a0b12"


class GophishContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Gophish",
                SupportedLanguage.fr: "Gophish",
            },
            color_dark="#2b8a3e",
            color_light="#2b8a3e",
            expose=True,
        )

        campaign_name = ContractText(
            key="campaign_name", label="Campaign name", mandatory=True
        )
        template_name = ContractText(
            key="template_name", label="Email template name", mandatory=True
        )
        page_name = ContractText(
            key="page_name", label="Landing page name", mandatory=True
        )
        smtp_name = ContractText(
            key="smtp_name", label="Sending profile (SMTP) name", mandatory=True
        )
        group_name = ContractText(
            key="group_name", label="Target group name", mandatory=True
        )
        url = ContractText(
            key="url", label="Phishing URL (recipient landing base URL)", mandatory=True
        )

        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.manual,
                    expectation_name="Human Response",
                    expectation_description="Recipient opened / clicked / submitted.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                )
            ],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    campaign_name,
                    template_name,
                    page_name,
                    smtp_name,
                    group_name,
                    url,
                    expectations,
                ]
            )
            .build_fields()
        )

        contract = Contract(
            contract_id=GOPHISH_CAMPAIGN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Gophish - Launch phishing campaign",
                SupportedLanguage.fr: "Gophish - Lancer une campagne de phishing",
            },
            fields=fields,
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.EMAIL_INFILTRATION.value],
        )

        return prepare_contracts([contract])
