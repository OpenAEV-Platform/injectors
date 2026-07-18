from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractText,
    ContractTextArea,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

CONTRACT_TYPE = "openaev_email"
CONTRACT_ID = "d3b4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f"


class EmailContracts:

    @staticmethod
    def build() -> List[Contract]:
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Email",
                SupportedLanguage.fr: "Email",
            },
            color_dark="#4caf50",
            color_light="#4caf50",
            expose=True,
        )
        attachment_field = ContractAttachment(
            key="attachments",
            label="Attachment",
            cardinality=ContractCardinality.Multiple,
        )
        email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="smtp_hostname", label="SMTP Hostname"))
            .mandatory(ContractText(key="smtp_port", label="SMTP Port"))
            .optional(
                ContractCheckbox(
                    key="smtp_use_tls",
                    label="Use TLS (STARTTLS)",
                    defaultValue=False,
                    mandatory=False,
                )
            )
            .optional(ContractText(key="smtp_username", label="SMTP Username"))
            .optional(ContractText(key="smtp_password", label="SMTP Password"))
            .mandatory(ContractText(key="from", label="From Email"))
            .optional(
                ContractText(key="mail_from", label="Mail From (envelope sender)")
            )
            .optional(ContractText(key="reply_to", label="Reply-To Email"))
            .mandatory(ContractText(key="to", label="To Email"))
            .optional(ContractText(key="cc", label="Cc (comma-separated emails)"))
            .optional(ContractText(key="bcc", label="Bcc (comma-separated emails)"))
            .mandatory(ContractText(key="subject", label="Subject"))
            .mandatory(ContractTextArea(key="body", label="Body"))
            .optional(attachment_field)
            .build_fields()
        )
        email_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email - Craft email",
                SupportedLanguage.fr: "Email - Rédiger un email",
            },
            fields=email_fields,
            outputs=[],
            manual=False,
            domains=[
                SecurityDomains.TABLE_TOP.value
            ],  # ty:ignore[invalid-argument-type]
        )
        return prepare_contracts([email_contract])
