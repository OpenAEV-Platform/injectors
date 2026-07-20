from enum import StrEnum
from typing import List

from email_smtp.contracts.craft_email import CraftEmail
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    SupportedLanguage,
    prepare_contracts,
)

TYPE = "openaev_email_smtp"


class InjectorKey(StrEnum):
    ATTACHMENTS = "attachments"


class EmailContractId(StrEnum):
    CRAFT_EMAIL = "d3b4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f"


class EmailContracts:

    @staticmethod
    def _base_contract_config() -> ContractConfig:
        return ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Email (SMTP)",
                SupportedLanguage.fr: "Email (SMTP)",
            },
            color_dark="#4caf50",
            color_light="#4caf50",
            expose=True,
        )

    @staticmethod
    def _base_outputs() -> list:
        return []

    def _build_contract(
        self, contract_id: str, contract_cls: type[CraftEmail]
    ) -> Contract:
        return contract_cls.contract(
            contract_id=contract_id,
            contract_config=self._base_contract_config(),
            contract_with_specific_fields=contract_cls.contract_with_specific_fields(),
            contract_with_specific_outputs=contract_cls.contract_with_specific_outputs(
                self._base_outputs()
            ),
        )

    def contracts(self) -> List[Contract]:
        email_contract_definitions = [
            (EmailContractId.CRAFT_EMAIL, CraftEmail),
        ]

        contracts = [
            self._build_contract(contract_id, contract_cls)
            for contract_id, contract_cls in email_contract_definitions
        ]

        return prepare_contracts(contracts)
