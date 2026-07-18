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

CONTRACT_TYPE = "openaev_slack"
# Stable id: re-registering updates the existing contract instead of duplicating it.
CONTRACT_ID = "b3f6a1d2-8c47-4e2a-9f1b-2a7c5d0e9f10"

# Contract field keys (shared with the payload builder and the injector).
KEY_CHANNEL = "channel"
KEY_CONTENT_TYPE = "content_type"
KEY_TITLE = "title"
KEY_MESSAGE = "message"
KEY_BLOCKS_JSON = "blocks_json"

# "How to render" selector values.
CONTENT_BLOCKS = "blocks"
CONTENT_TEXT = "text"
CONTENT_TYPES = {
    CONTENT_BLOCKS: "Block Kit",
    CONTENT_TEXT: "Plain text",
}


class SlackContracts:

    @staticmethod
    def build() -> List[Contract]:
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Slack",
                SupportedLanguage.fr: "Slack",
            },
            color_dark="#611f69",
            color_light="#611f69",
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

        channel = ContractText(
            key=KEY_CHANNEL,
            label="Channel or user (e.g. C0123456789, #general, or a user id U0123...)",
            mandatory=True,
        )
        content_type = ContractSelect(
            key=KEY_CONTENT_TYPE,
            label="Message format",
            defaultValue=[CONTENT_BLOCKS],
            mandatory=True,
            choices=dict(CONTENT_TYPES),
        )
        title = ContractText(
            key=KEY_TITLE,
            label="Title",
            mandatory=True,
        )
        message = ContractTextArea(
            key=KEY_MESSAGE,
            label="Message",
            mandatory=True,
        )
        # Advanced: paste a full Block Kit "blocks" array. When set (and format =
        # Block Kit) it is sent verbatim and replaces the auto-built layout.
        # Title and message remain mandatory: they still provide the plain-text
        # fallback Slack uses for notifications and previews.
        blocks_json = ContractTextArea(
            key=KEY_BLOCKS_JSON,
            label=(
                "Custom Block Kit blocks JSON (optional, replaces the auto-built "
                "layout; title/message still provide the notification fallback)"
            ),
            mandatory=False,
            visibleConditionFields=[content_type.key],
            visibleConditionValues={content_type.key: CONTENT_BLOCKS},
        )

        slack_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(channel)
            .mandatory(content_type)
            .mandatory(title)
            .mandatory(message)
            .optional(blocks_json)
            .optional(expectations)
            .build_fields()
        )
        slack_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Slack - Send message",
                SupportedLanguage.fr: "Slack - Envoyer un message",
            },
            fields=slack_fields,
            outputs=[],
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
        return prepare_contracts([slack_contract])
