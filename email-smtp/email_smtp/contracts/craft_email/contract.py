from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractText,
    ContractTextArea,
    SupportedLanguage,
)
from pyoaev.security_domain.types import SecurityDomains


class CraftEmail:

    @classmethod
    def contract_with_specific_fields(cls) -> List[ContractElement]:
        attachment_field = ContractAttachment(
            key="attachments",
            label="Attachment",
            cardinality=ContractCardinality.Multiple,
        )
        return (
            ContractBuilder()
            .mandatory(ContractText(key="smtp_hostname", label="SMTP Hostname"))
            .mandatory(ContractText(key="smtp_port", label="SMTP Port"))
            .optional(
                ContractCheckbox(
                    key="smtp_use_tls",
                    label="Use TLS (STARTTLS)",
                    defaultValue=False,
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

    @staticmethod
    def contract_with_specific_outputs(
        base_outputs: List[ContractOutputElement],
    ) -> List[ContractOutputElement]:
        specific_outputs: List[ContractOutputElement] = []
        return (
            ContractBuilder()
            .add_outputs(base_outputs + specific_outputs)
            .build_outputs()
        )

    @staticmethod
    def contract(
        contract_id: str,
        contract_config: ContractConfig,
        contract_with_specific_fields: List[ContractElement],
        contract_with_specific_outputs: List[ContractOutputElement],
    ) -> Contract:
        return Contract(
            contract_id=contract_id,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email (SMTP) - Craft email",
                SupportedLanguage.fr: "Email (SMTP) - Rédiger un email",
            },
            fields=contract_with_specific_fields,
            outputs=contract_with_specific_outputs,
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
