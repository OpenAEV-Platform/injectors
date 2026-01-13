from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractText,
    ContractTuple,
    SupportedLanguage,
)


class CriticalPortsAndExposedAdminInterface:

    @staticmethod
    def contract_with_specific_fields(
            base_fields: list[ContractElement],
            source_selector_key:str,
            target_selector_field:str
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
            ContractTuple(
                key="port",
                label="Port",
                mandatory=True,
                defaultValue=["20","21","22","23","25","53","80","110","111","135","139","143","443","445","993","995","1723","3306","3389","5900","8080"],
                **(mandatory_conditions | visible_conditions),
            ),
            ContractText(
                key="hostname",
                label="Hostname",
                mandatory=True,
                **(mandatory_conditions | visible_conditions),
            ),
            ContractText(
                key="organization",
                label="Organization",
                **visible_conditions,
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
                SupportedLanguage.en: "Shodan - Critical ports and exposed admin interface",
                SupportedLanguage.fr: "Shodan - Ports critiques et interface d'administration exposée",
            },
            fields=contract_with_specific_fields,
            outputs=contract_with_specific_outputs,
            manual=False,
        )