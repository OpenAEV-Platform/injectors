from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
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
CONTRACT_ID = "d3b4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f"  # Generated a new UUID


class EmailContracts:

    @staticmethod
    def build() -> List[Contract]:
        # Config
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
        # Fields
        email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="smtp_hostname", label="SMTP Hostname"))
            .mandatory(ContractText(key="smtp_port", label="SMTP Port"))
            .mandatory(ContractCheckbox(key="smtp_use_tls", label="Use TLS (STARTTLS)"))
            .optional(ContractText(key="smtp_username", label="SMTP Username"))
            .optional(ContractText(key="smtp_password", label="SMTP Password"))
            .mandatory(ContractText(key="from", label="From Email"))
            .mandatory(ContractText(key="to", label="To Email"))
            .mandatory(ContractText(key="subject", label="Subject"))
            .mandatory(ContractTextArea(key="body", label="Body"))
            .build_fields()
        )
        email_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email - Send email",
                SupportedLanguage.fr: "Email - Envoyer un email",
            },
            fields=email_fields,
            outputs=[],
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
        return prepare_contracts([email_contract])
