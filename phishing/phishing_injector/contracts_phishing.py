from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractSelect,
    ContractText,
    ContractTextArea,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_phishing"

PHISHING_CAMPAIGN_CONTRACT = "c3f4a5b6-6a77-4c84-9b92-7e8f9a0b1c23"

TEMPLATE_CHOICES = {
    "password_reset": "Password reset",
    "mfa_reenrollment": "MFA re-enrollment",
    "shared_document": "Shared document",
}


class PhishingContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Phishing",
                SupportedLanguage.fr: "Hameçonnage",
            },
            color_dark="#e8590c",
            color_light="#e8590c",
            expose=True,
        )

        campaign_name = ContractText(
            key="campaign_name", label="Campaign name", mandatory=True
        )
        recipients = ContractTextArea(
            key="recipients",
            label="Recipient emails (comma, semicolon or newline separated)",
            mandatory=True,
        )
        template = ContractSelect(
            key="template",
            label="Email template",
            defaultValue=["password_reset"],
            mandatory=True,
            choices=TEMPLATE_CHOICES,
        )
        custom_html = ContractTextArea(
            key="custom_html",
            label="Custom HTML (optional, overrides the template; use {link} and "
            "{pixel} placeholders)",
            mandatory=False,
        )
        subject = ContractText(
            key="subject",
            label="Subject (optional, overrides the template subject)",
            mandatory=False,
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
                    recipients,
                    template,
                    subject,
                    custom_html,
                    expectations,
                ]
            )
            .build_fields()
        )

        contract = Contract(
            contract_id=PHISHING_CAMPAIGN_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Phishing - Launch native campaign",
                SupportedLanguage.fr: "Hameçonnage - Lancer une campagne native",
            },
            fields=fields,
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.EMAIL_INFILTRATION.value],
        )

        return prepare_contracts([contract])
