from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractText,
    ContractTextArea,
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
        # Fields
        teams_fields: List[ContractElement] = (
            ContractBuilder()
            .mandatory(ContractText(key="uri", label="Power Automate URL"))
            .mandatory(ContractText(key="title", label="Title"))
            .mandatory(ContractTextArea(key="message", label="Message"))
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
