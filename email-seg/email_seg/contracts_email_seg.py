from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_email_seg"

SEG_ASSESSMENT_CONTRACT = "a1d2e3f4-4e55-4a62-8f70-5c6d7e8f9a01"

PAYLOAD_CHOICES = {
    "eicar_body": "EICAR test string in the email body",
    "eicar_attachment": "EICAR test file attachment (eicar.com)",
    "eicar_zip": "EICAR test file inside a zip archive (evasion)",
    "malicious_url": "Test URL in the body (URL filtering)",
}


class EmailSegContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Email Gateway (SEG)",
                SupportedLanguage.fr: "Passerelle e-mail (SEG)",
            },
            color_dark="#d13438",
            color_light="#d13438",
            expose=True,
        )

        smtp_host = ContractText(key="smtp_host", label="SMTP host", mandatory=True)
        smtp_port = ContractText(
            key="smtp_port", label="SMTP port", mandatory=True, defaultValue=["587"]
        )
        smtp_username = ContractText(
            key="smtp_username", label="SMTP username", mandatory=False
        )
        smtp_password = ContractText(
            key="smtp_password", label="SMTP password", mandatory=False
        )
        smtp_use_tls = ContractCheckbox(
            key="smtp_use_tls", label="Use STARTTLS", defaultValue=True
        )
        mail_from = ContractText(key="mail_from", label="From address", mandatory=True)
        mail_to = ContractText(key="mail_to", label="Recipient mailbox", mandatory=True)
        subject = ContractText(
            key="subject",
            label="Subject",
            mandatory=False,
            defaultValue=["OpenAEV email gateway assessment"],
        )
        payload = ContractSelect(
            key="payload",
            label="Test payload",
            defaultValue=["eicar_body"],
            mandatory=True,
            choices=PAYLOAD_CHOICES,
        )
        malicious_url = ContractText(
            key="malicious_url",
            label="Test URL (for the URL filtering payload)",
            mandatory=False,
        )

        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.prevention,
                    expectation_name="Prevention",
                    expectation_description="The gateway blocks or strips the payload.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
                Expectation(
                    expectation_type=ExpectationType.detection,
                    expectation_name="Detection",
                    expectation_description="The gateway detects the payload.",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
            ],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    smtp_host,
                    smtp_port,
                    smtp_username,
                    smtp_password,
                    smtp_use_tls,
                    mail_from,
                    mail_to,
                    subject,
                    payload,
                    malicious_url,
                    expectations,
                ]
            )
            .build_fields()
        )

        contract = Contract(
            contract_id=SEG_ASSESSMENT_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email Gateway - Send test payload",
                SupportedLanguage.fr: "Passerelle e-mail - Envoyer une charge de test",
            },
            fields=fields,
            outputs=ContractBuilder().build_outputs(),
            manual=False,
            domains=[SecurityDomains.EMAIL_INFILTRATION.value],
        )

        return prepare_contracts([contract])
