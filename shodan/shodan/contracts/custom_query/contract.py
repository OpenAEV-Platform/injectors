from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractSelect,
    ContractText,
    SupportedLanguage,
)


class CustomQuery:

    @staticmethod
    def output_trace_config():
        return {
            "header": {
                "title": "SHODAN - CUSTOM QUERY",
                "subtitle": None,
            },
            "sections_config": {
                "header": {
                    "icon": "CONFIG",
                    "title": "[CONFIG] Summary of all configurations used for the contract.",
                },
                "keys_list_to_string": [],
                "keys_to_exclude": [],
            },
            "sections_info": {
                "header": {
                    "icon": "INFO",
                    "title": "[INFO] The Shodan information for the remaining credits and the user's plan.",
                },
                "keys_list_to_string": [],
                "keys_to_exclude": [],
            },
            "sections_external_api": {
                "header": {
                    "icon": "API",
                    "title": "[SHODAN] Call API completed",
                },
                "call_success": {
                    "icon": "SUCCESS",
                    "title": "Call Success",
                    "count_at_path": "matches",
                },
                "call_failed": {
                    "icon": "FAILED",
                    "title": "Call Failed",
                },
            },
            "tables": [
                {
                    "header": {
                        "icon": "SEARCH",
                        "title": None,
                    },
                    "config": {
                        "search_entity": None,
                        "columns": [],
                    },
                }
            ],
            "options": {
                # "split_output": False,
                "show_header": {
                    "is_active": True,
                    "show_subtitle": True,
                },
                "show_sections": {
                    "is_active": True,
                    "sec_config": True,
                    "sec_info": True,
                    "sec_external_api": True,
                },
                "show_tables": {
                    "is_active": False,
                    "show_lines": True,
                    "max_display_by_cell": 4,
                    "show_index": {
                        "is_active": False,
                        "index_start": 1,
                    },
                },
                "show_separator": {
                    "is_active": False,
                },
                "show_json": {
                    "is_active": True,
                    "indent": 2,
                    "sort_keys": False,
                },
            },
        }

    @staticmethod
    def contract_with_specific_fields(
        base_fields: list[ContractElement],
        source_selector_key: str,
        target_selector_field: str,
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
            ContractSelect(
                key="http_method",
                label="HTTP Method",
                defaultValue=["get"],
                choices={
                    "get": "GET",
                    "post": "POST",
                    "put": "PUT",
                    "delete": "DELETE",
                },
                **(mandatory_conditions | visible_conditions),
            ),
            ContractText(
                key="custom_query",
                label="Custom Query",
                **(mandatory_conditions | visible_conditions),
            ),
        ]

        contract_fields = (
            ContractBuilder().add_fields(base_fields + specific_fields).build_fields()
        )
        return contract_fields

    @staticmethod
    def contract_with_specific_outputs(
        base_outputs: list[ContractOutputElement],
    ) -> list[ContractOutputElement]:
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
        contract_with_specific_outputs: list[ContractOutputElement],
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
