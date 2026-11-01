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

CONTRACT_TYPE = "openaev_teams"
# Stable id: re-registering updates the existing contract instead of duplicating it.
CONTRACT_ID = "c98e373e-3265-4aee-a2bb-36f7cb81e93e"

# Contract field keys (shared with the payload builder and the injector).
KEY_TARGET_TYPE = "target_type"
KEY_TEAM_ID = "team_id"
KEY_CHANNEL_ID = "channel_id"
KEY_CHAT_ID = "chat_id"
KEY_CONTENT_TYPE = "content_type"
KEY_TITLE = "title"
KEY_MESSAGE = "message"
KEY_CARD_JSON = "card_json"

# "Where to post" selector values.
TARGET_CHANNEL = "channel"
TARGET_CHAT = "chat"
TARGET_TYPES = {
    TARGET_CHANNEL: "Channel (team channel)",
    TARGET_CHAT: "Chat (group or 1:1 chat)",
}

# "How to render" selector values.
CONTENT_CARD = "card"
CONTENT_TEXT = "text"
CONTENT_TYPES = {
    CONTENT_CARD: "Adaptive Card",
    CONTENT_TEXT: "Plain text",
}


class TeamsContracts:

    @staticmethod
    def build() -> List[Contract]:
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Microsoft Teams",
                SupportedLanguage.fr: "Microsoft Teams",
            },
            color_dark="#4b53bc",
            color_light="#4b53bc",
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

        target_type = ContractSelect(
            key=KEY_TARGET_TYPE,
            label="Post to",
            defaultValue=[TARGET_CHANNEL],
            mandatory=True,
            choices=dict(TARGET_TYPES),
        )
        # Channel target: team id + channel id (visible + mandatory only for channels).
        channel_condition = {
            "mandatoryConditionFields": [target_type.key],
            "mandatoryConditionValues": {target_type.key: TARGET_CHANNEL},
            "visibleConditionFields": [target_type.key],
            "visibleConditionValues": {target_type.key: TARGET_CHANNEL},
        }
        team_id = ContractText(
            key=KEY_TEAM_ID,
            label="Team ID (group id)",
            mandatory=False,
            **channel_condition,
        )
        channel_id = ContractText(
            key=KEY_CHANNEL_ID,
            label="Channel ID (e.g. 19:...@thread.tacv2)",
            mandatory=False,
            **channel_condition,
        )
        # Chat target: chat id (visible + mandatory only for chats).
        chat_id = ContractText(
            key=KEY_CHAT_ID,
            label="Chat ID (e.g. 19:...@thread.v2)",
            mandatory=False,
            mandatoryConditionFields=[target_type.key],
            mandatoryConditionValues={target_type.key: TARGET_CHAT},
            visibleConditionFields=[target_type.key],
            visibleConditionValues={target_type.key: TARGET_CHAT},
        )

        content_type = ContractSelect(
            key=KEY_CONTENT_TYPE,
            label="Message format",
            defaultValue=[CONTENT_CARD],
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
        # Advanced: paste a full Adaptive Card JSON. When set (and format = Adaptive
        # Card), it is sent verbatim; otherwise a card is auto-built from title + message.
        card_json = ContractTextArea(
            key=KEY_CARD_JSON,
            label="Custom Adaptive Card JSON (optional, overrides title/message)",
            mandatory=False,
            visibleConditionFields=[content_type.key],
            visibleConditionValues={content_type.key: CONTENT_CARD},
        )

        teams_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(target_type)
            .optional(team_id)
            .optional(channel_id)
            .optional(chat_id)
            .mandatory(content_type)
            .mandatory(title)
            .mandatory(message)
            .optional(card_json)
            .optional(expectations)
            .build_fields()
        )
        teams_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Teams - Send message",
                SupportedLanguage.fr: "Teams - Envoyer un message",
            },
            fields=teams_fields,
            outputs=[],
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
        return prepare_contracts([teams_contract])
