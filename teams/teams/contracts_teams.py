from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractText,
    ContractTextArea,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

CONTRACT_TYPE = "openaev_teams"
CONTRACT_ID = "c98e373e-3265-4aee-a2bb-36f7cb81e93e"


class TeamsContracts:

    @staticmethod
    def build() -> List[Contract]:
        # Config
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "Teams",
                SupportedLanguage.fr: "Teams",
            },
            color_dark="#00bcd4",
            color_light="#00bcd4",
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
        # Fields
        teams_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="Power Automate URL"))
            .mandatory(ContractText(key="title", label="Title"))
            .mandatory(ContractTextArea(key="message", label="Message"))
            .optional(expectations)
            .build_fields()
        )
        teams_contract = Contract(
            contract_id=CONTRACT_ID,
            config=contract_config,
            label={
                SupportedLanguage.en: "Teams - Channel message",
                SupportedLanguage.fr: "Teams - Message dans un canal",
            },
            fields=teams_fields,
            outputs=[],
            manual=False,
            domains=[SecurityDomains.TABLE_TOP.value],
        )
        return prepare_contracts([teams_contract])
