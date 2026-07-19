from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAttachment,
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

CONTRACT_TYPE = "openaev_email_gws"
# Stable id: re-registering updates the existing contract instead of duplicating it.
CONTRACT_ID = "c4d5e6f7-8a9b-4c0d-9e1f-2a3b4c5d6e7f"

# Contract field keys (shared with the payload builder and the injector).
KEY_FROM = "from"
KEY_TO = "to"
KEY_CC = "cc"
KEY_BCC = "bcc"
KEY_REPLY_TO = "reply_to"
KEY_SUBJECT = "subject"
KEY_BODY = "body"
KEY_BODY_FORMAT = "body_format"
KEY_ATTACHMENTS = "attachments"

# Body format selector values (mapped to the MIME body subtype).
BODY_FORMAT_HTML = "html"
BODY_FORMAT_TEXT = "text"
BODY_FORMATS = {
    BODY_FORMAT_HTML: "HTML",
    BODY_FORMAT_TEXT: "Plain text",
}


class EmailGWSContracts:

    @staticmethod
    def build() -> List[Contract]:
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Email (Google Workspace)",
                SupportedLanguage.fr: "Email (Google Workspace)",
            },
            color_dark="#ea4335",
            color_light="#ea4335",
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
            label="Attachments",
            cardinality=ContractCardinality.Multiple,
        )

        email_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(
                ContractText(
                    key=KEY_FROM,
                    label="From (Workspace user to send as, e.g. alerts@yourdomain.com)",
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
            .optional(attachment_field)
            .optional(expectations)
            .build_fields()
        )
        email_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Email (Google Workspace) - Send email",
                SupportedLanguage.fr: "Email (Google Workspace) - Envoyer un email",
            },
            fields=email_fields,
            outputs=[],
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
        return prepare_contracts([email_contract])
