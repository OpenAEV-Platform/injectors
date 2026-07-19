from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAttachment,
    ContractCardinality,
    ContractCheckbox,
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

CONTRACT_TYPE = "openaev_email_m365"
# Stable id: re-registering updates the existing contract instead of duplicating it.
CONTRACT_ID = "a1c2e3f4-5b6d-4e7f-8a9b-0c1d2e3f4a5b"

# Contract field keys (shared with the payload builder and the injector).
KEY_FROM = "from"
KEY_TO = "to"
KEY_CC = "cc"
KEY_BCC = "bcc"
KEY_REPLY_TO = "reply_to"
KEY_SUBJECT = "subject"
KEY_BODY = "body"
KEY_BODY_FORMAT = "body_format"
KEY_SAVE_TO_SENT = "save_to_sent"
KEY_ATTACHMENTS = "attachments"

# Body format selector values (mapped to Microsoft Graph body contentType).
BODY_FORMAT_HTML = "html"
BODY_FORMAT_TEXT = "text"
BODY_FORMATS = {
    BODY_FORMAT_HTML: "HTML",
    BODY_FORMAT_TEXT: "Plain text",
}


class EmailM365Contracts:

    @staticmethod
    def build() -> List[Contract]:
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Email (Microsoft 365)",
                SupportedLanguage.fr: "Email (Microsoft 365)",
            },
            color_dark="#0078d4",
            color_light="#0078d4",
            expose=True,
        )
        expectation_items = [
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
            ),
            Expectation(
                expectation_type=ExpectationType.prevention,
                expectation_name="Prevention",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
            ),
        ]
        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            availableExpectations=expectation_items,
        )
        attachment_field = ContractAttachment(
            key=KEY_ATTACHMENTS,
            label="Attachment",
            cardinality=ContractCardinality.Multiple,
        )

        email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(
                ContractText(
                    key=KEY_FROM,
                    label="From (sender mailbox in the tenant, e.g. alerts@contoso.com)",
                )
            )
            .mandatory(ContractText(key=KEY_TO, label="To (comma-separated emails)"))
            .optional(ContractText(key=KEY_CC, label="Cc (comma-separated emails)"))
            .optional(ContractText(key=KEY_BCC, label="Bcc (comma-separated emails)"))
            .optional(ContractText(key=KEY_REPLY_TO, label="Reply-To email"))
            .mandatory(ContractText(key=KEY_SUBJECT, label="Subject"))
            .mandatory(
                ContractSelect(
                    key=KEY_BODY_FORMAT,
                    label="Body format",
                    defaultValue=[BODY_FORMAT_HTML],
                    mandatory=True,
                    choices=dict(BODY_FORMATS),
                )
            )
            .mandatory(ContractTextArea(key=KEY_BODY, label="Body"))
            .optional(
                ContractCheckbox(
                    key=KEY_SAVE_TO_SENT,
                    label="Save to Sent Items",
                    defaultValue=True,
                    mandatory=False,
                )
            )
            .optional(attachment_field)
            .optional(expectations)
            .build_fields()
        )
        email_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email (Microsoft 365) - Send email",
                SupportedLanguage.fr: "Email (Microsoft 365) - Envoyer un email",
            },
            fields=email_fields,
            outputs=[],
            manual=False,
            domains=[
                SecurityDomains.TABLE_TOP.value
            ],  # type: ignore[invalid-argument-type]
        )
        return prepare_contracts([email_contract])
