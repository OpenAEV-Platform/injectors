from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
    ContractCardinality,
    ContractConfig,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)

from injector_common.constants import (
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.targets import TargetProperty, target_property_choices_dict
from nuclei.nuclei_contracts.nuclei_constants import CONTRACT_LABELS, TYPE


class NucleiContracts:

    @staticmethod
    def base_contract_config():
        return ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Nuclei Scan",
                SupportedLanguage.fr: "Nuclei Scan",
            },
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

    @staticmethod
    def core_contract_fields():
        # -- FIELDS --
        target_selector = ContractSelect(
            key=TARGET_SELECTOR_KEY,
            label="Type of targets",
            defaultValue=["asset-groups"],
            mandatory=True,
            choices={
                "assets": "Assets",
                "manual": "Manual",
                "asset-groups": "Asset groups",
            },
        )
        targets_assets = ContractAsset(
            cardinality=ContractCardinality.Multiple,
            label="Targeted assets",
            mandatory=False,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "assets"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "assets"},
        )
        target_asset_groups = ContractAssetGroup(
            cardinality=ContractCardinality.Multiple,
            label="Targeted asset groups",
            mandatory=False,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "asset-groups"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "asset-groups"},
        )
        target_property_selector = ContractSelect(
            key=TARGET_PROPERTY_SELECTOR_KEY,
            label="Targeted assets property",
            defaultValue=[TargetProperty.AUTOMATIC.name.lower()],
            mandatory=False,
            choices=target_property_choices_dict,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: ["assets", "asset-groups"]},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: ["assets", "asset-groups"]},
        )
        targets_manual = ContractText(
            key=TARGETS_KEY,
            label="Manual targets (comma-separated)",
            mandatory=False,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "manual"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "manual"},
        )
        template_path = ContractText(
            key="template",
            label="Manual template path (-t)",
            mandatory=False,
        )
        options = ContractText(
            key="options",
            label="Options",
            mandatory=False,
        )
        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.vulnerability,
                    expectation_name="Not vulnerable",
                    expectation_description="",
                    expectation_score=100,
                    expectation_expectation_group=False,
                )
            ],
        )

        return [
            target_selector,
            targets_assets,
            target_asset_groups,
            target_property_selector,
            targets_manual,
            expectations,
            template_path,
            options,
        ]

    @staticmethod
    def core_outputs():
        output_vulns = ContractOutputElement(
            type=ContractOutputType.CVE,
            field="cve",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        output_others = ContractOutputElement(
            type=ContractOutputType.Text,
            field="others",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["nuclei"],
        )
        return [output_vulns, output_others]

    @staticmethod
    def build_contract(
        contract_id,
        external_id,
        contract_config,
        contract_fields,
        contract_outputs,
        label_en,
        label_fr,
        domains,
    ):
        return Contract(
            contract_id=contract_id,
            external_id=external_id,
            config=contract_config,
            label={
                SupportedLanguage.en: label_en,
                SupportedLanguage.fr: label_fr,
            },
            fields=ContractBuilder().add_fields(contract_fields).build_fields(),
            outputs=ContractBuilder().add_outputs(contract_outputs).build_outputs(),
            manual=False,
            domains=domains,
        )

    @staticmethod
    def build_static_contracts():
        return prepare_contracts(
            [
                NucleiContracts.build_contract(
                    cid,
                    None,
                    NucleiContracts.base_contract_config(),
                    NucleiContracts.core_contract_fields(),
                    NucleiContracts.core_outputs(),
                    f"Nuclei - {en}",
                    f"Nuclei - {fr}",
                    domains,
                )
                for cid, (en, fr, domains) in CONTRACT_LABELS.items()
            ]
        )
