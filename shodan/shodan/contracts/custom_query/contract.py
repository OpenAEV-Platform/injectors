from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractText,
    SupportedLanguage,
)


class CustomQuery:

    @staticmethod
    def contract_with_specific_fields(
            base_fields: list[ContractElement],
            source_selector_key:str,
            target_selector_field:str,
    ) -> list[ContractElement]:

        mandatory_conditions = dict(
            mandatoryConditionFields=[source_selector_key],
            mandatoryConditionValues={source_selector_key: target_selector_field},
        )

        visible_conditions = dict(
            visibleConditionFields=[source_selector_key],
            visibleConditionValues={source_selector_key: target_selector_field},
        )

        specific_fields = [
            ContractText(
                key="custom_request_overview",
                label="Custom Request Overview",
                readOnly=True,
                **visible_conditions,
            ),
            ContractText(
                key="custom_request",
                label="Custom Request",
                mandatory=True,
                **(mandatory_conditions | visible_conditions),
            ),
        ]

        contract_fields = (
            ContractBuilder()
            .add_fields(base_fields + specific_fields)
            .build_fields()
        )
        return contract_fields

    @staticmethod
    def contract_with_specific_outputs(base_outputs: list[ContractOutputElement]) -> list[ContractOutputElement]:
        specific_outputs = []
        contract_outputs = (
            ContractBuilder()
            .add_outputs(base_outputs + specific_outputs)
            .build_outputs()
        )
        return contract_outputs

    @staticmethod
    def contract(
            contract_id: str,
            contract_config: ContractConfig,
            contract_with_specific_fields: list[ContractElement],
            contract_with_specific_outputs: list[ContractOutputElement]
    ) -> Contract:
        return Contract(
            contract_id=contract_id,
            config=contract_config,
            label={
                SupportedLanguage.en: "Shodan - Custom query",
                SupportedLanguage.fr: "Shodan - Requête personnalisée",
            },
            fields=contract_with_specific_fields,
            outputs=contract_with_specific_outputs,
            manual=False,
        )
