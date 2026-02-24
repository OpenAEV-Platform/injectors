from typing import TYPE_CHECKING

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractConfig,
    ContractElement,
    ContractOutputElement,
    ContractText,
    SupportedLanguage,
)

if TYPE_CHECKING:
    from shodan.contracts.shodan_contracts import TargetSelectorField


class CVEEnumeration:

    @staticmethod
    def output_trace_config():
        return {
            "header": {
                "title": "SHODAN - CVE ENUMERATION",
                "subtitle": None,
            },
            "sections_config": {
                "header": {
                    "icon": "CONFIG",
                    "title": "[CONFIG] Summary of all configurations used for the contract.",
                },
                "keys_list_to_string": ["hostnames"],
                "keys_to_exclude": [
                    "expectations",
                    "selector_key",
                    "asset_ids",
                    "ips",
                    "seen_ips",
                    "assets",
                ],
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
                        "columns": [
                            {
                                "title": "Hostnames",
                                "path": "matches.hostnames",
                                "mode": "single",
                            },
                            {
                                "title": "IP",
                                "path": "matches.ip_str",
                                "mode": "align_to_single",
                            },
                            {
                                "title": "Port",
                                "path": "matches.port",
                                "mode": "align_to_single",
                            },
                            {
                                "title": "Vulnerabilities (score)",
                                "path": "matches.vulns.*",
                                "use_key": True,
                                "extra": "matches.vulns.*.cvss",
                                "mode": "align_to_single",
                            },
                        ],
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
                    "is_active": True,
                    "show_lines": True,
                    "max_display_by_cell": 10,
                    "show_index": {
                        "is_active": False,
                        "index_start": 1,
                    },
                },
                "show_separator": {
                    "is_active": False,
                },
                "show_json": {
                    "is_active": False,
                    "indent": 2,
                    "sort_keys": False,
                },
            },
        }

    @classmethod
    def _build_conditions(
        cls,
        source_selector: str,
        target_selector: list[str],
        mandatory: bool = True,
        visible: bool = True,
    ):
        conditions = {}
        if mandatory:
            conditions |= dict(
                mandatoryConditionFields=[source_selector],
                mandatoryConditionValues={source_selector: target_selector},
            )
        if visible:
            conditions |= dict(
                visibleConditionFields=[source_selector],
                visibleConditionValues={source_selector: target_selector},
            )
        return conditions

    @classmethod
    def contract_with_specific_fields(
        cls,
        base_fields: list[ContractElement],
        source_selector_key: str,
        target_selector_field: type["TargetSelectorField"],
    ) -> list[ContractElement]:

        manual_target_selector = [target_selector_field.MANUAL.key]

        specific_fields = [
            ContractText(
                key="hostname",
                label="Hostname",
                **cls._build_conditions(
                    source_selector=source_selector_key,
                    target_selector=manual_target_selector,
                ),
            ),
            ContractText(
                key="organization",
                label="Organization",
                **cls._build_conditions(
                    source_selector=source_selector_key,
                    target_selector=manual_target_selector,
                    mandatory=False,
                ),
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
                SupportedLanguage.en: "Shodan - CVE Enumeration",
                SupportedLanguage.fr: "Shodan - Énumération des CVE",
            },
            fields=contract_with_specific_fields,
            outputs=contract_with_specific_outputs,
            manual=False,
        )
