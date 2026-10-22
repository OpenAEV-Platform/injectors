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
    ContractTextArea,
    Expectation,
    ExpectationType,
    SecurityPlatformType,
    SupportedLanguage,
    prepare_contracts,
)

from injector_common.constants import (
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.targets import TargetProperty, target_property_choices_dict
from strix.strix_contracts.strix_constants import (
    CODE_ASSESSMENT_CONTRACT,
    CONTRACT_LABELS,
    NETWORK_ASSESSMENT_CONTRACT,
    TYPE,
)

# Contract field keys specific to Strix.
REPOSITORY_KEY = "repository"
LLM_MODEL_KEY = "llm_model"
LLM_API_BASE_KEY = "llm_api_base"
INSTRUCTION_KEY = "instruction"
SCAN_MODE_KEY = "scan_mode"


class StrixContracts:

    @staticmethod
    def base_contract_config():
        return ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Strix",
                SupportedLanguage.fr: "Strix",
            },
            color_dark="#2b9246",
            color_light="#2b9246",
            expose=True,
        )

    @staticmethod
    def _llm_fields():
        # Per-inject LLM overrides. Non-secret only: the model id and an optional
        # OpenAI-compatible base URL. The API key is deliberately NOT a field
        # (pyoaev has no masked field type -> it would be stored/rendered in
        # plaintext); it stays in the injector configuration (STRIX_LLM_API_KEY).
        return [
            ContractText(
                key=LLM_MODEL_KEY,
                label=(
                    "LLM model (LiteLLM id, overrides the injector default) - "
                    "e.g. anthropic/claude-sonnet-4-5"
                ),
                mandatory=False,
            ),
            ContractText(
                key=LLM_API_BASE_KEY,
                label=(
                    "LLM API base URL (optional; leave empty for the provider "
                    "default endpoint)"
                ),
                mandatory=False,
            ),
        ]

    @staticmethod
    def _scan_mode_field():
        return ContractSelect(
            key=SCAN_MODE_KEY,
            label="Scan mode (overrides the injector default)",
            defaultValue=[],
            mandatory=False,
            choices={
                "quick": "Quick",
                "standard": "Standard",
                "deep": "Deep",
            },
        )

    @staticmethod
    def _instruction_field():
        return ContractTextArea(
            key=INSTRUCTION_KEY,
            label="Custom instructions (focus areas, test credentials, scope notes)",
            mandatory=False,
        )

    @staticmethod
    def _expectation_items():
        return [
            Expectation(
                expectation_type=ExpectationType.detection,
                expectation_name="Detection",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
                expectation_expected_security_platform_types=[
                    SecurityPlatformType.XDR,
                    SecurityPlatformType.SIEM,
                    SecurityPlatformType.NDR,
                ],
            ),
            Expectation(
                expectation_type=ExpectationType.prevention,
                expectation_name="Prevention",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
                expectation_expected_security_platform_types=[
                    SecurityPlatformType.XDR,
                    SecurityPlatformType.NDR,
                ],
            ),
            Expectation(
                expectation_type=ExpectationType.vulnerability,
                expectation_name="Not vulnerable",
                expectation_description="",
                expectation_score=100,
                expectation_expectation_group=False,
                expectation_is_predefined=True,
            ),
        ]

    @staticmethod
    def _expectations_field():
        items = StrixContracts._expectation_items()
        return ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            availableExpectations=items,
            predefinedExpectations=items,
        )

    @staticmethod
    def network_contract_fields():
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
            label="Manual targets (comma-separated URLs / domains / IPs)",
            mandatory=False,
            mandatoryConditionFields=[target_selector.key],
            mandatoryConditionValues={target_selector.key: "manual"},
            visibleConditionFields=[target_selector.key],
            visibleConditionValues={target_selector.key: "manual"},
        )
        return [
            target_selector,
            targets_assets,
            target_asset_groups,
            target_property_selector,
            targets_manual,
            StrixContracts._scan_mode_field(),
            StrixContracts._instruction_field(),
            *StrixContracts._llm_fields(),
            StrixContracts._expectations_field(),
        ]

    @staticmethod
    def code_contract_fields():
        repository = ContractText(
            key=REPOSITORY_KEY,
            label="Code target (git repository URL or path mounted in the sandbox)",
            mandatory=True,
        )
        return [
            repository,
            StrixContracts._scan_mode_field(),
            StrixContracts._instruction_field(),
            *StrixContracts._llm_fields(),
            StrixContracts._expectations_field(),
        ]

    @staticmethod
    def core_outputs():
        output_expectation_signatures = ContractOutputElement(
            type=ContractOutputType.ExpectationSignature,
            field="expectation_signatures",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["strix"],
        )
        output_vulns = ContractOutputElement(
            type=ContractOutputType.CVE,
            field="cve",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["strix"],
        )
        output_vulnerability = ContractOutputElement(
            type=ContractOutputType.Vulnerability,
            field="vulnerability",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["strix"],
        )
        output_others = ContractOutputElement(
            type=ContractOutputType.Text,
            field="others",
            isMultiple=True,
            isFindingCompatible=True,
            labels=["strix"],
        )
        # Raw executive report / run summary: never a visible Finding, but stays
        # usable as a chaining/event filter (same pattern as the Nuclei injector).
        output_action_output = ContractOutputElement(
            type=ContractOutputType.ActionOutput,
            field="action_output",
            isMultiple=False,
            isFindingCompatible=False,
            labels=["strix"],
        )
        return [
            output_expectation_signatures,
            output_vulns,
            output_vulnerability,
            output_others,
            output_action_output,
        ]

    @staticmethod
    def build_contract(
        contract_id,
        contract_fields,
        label_en,
        label_fr,
        domains,
        attack_patterns,
    ):
        return Contract(
            contract_id=contract_id,
            external_id=None,
            config=StrixContracts.base_contract_config(),
            label={
                SupportedLanguage.en: label_en,
                SupportedLanguage.fr: label_fr,
            },
            fields=ContractBuilder().add_fields(contract_fields).build_fields(),
            outputs=ContractBuilder()
            .add_outputs(StrixContracts.core_outputs())
            .build_outputs(),
            manual=False,
            domains=domains,
            contract_attack_patterns_external_ids=attack_patterns,
        )

    @staticmethod
    def build_static_contracts():
        fields_by_contract = {
            NETWORK_ASSESSMENT_CONTRACT: (
                StrixContracts.network_contract_fields(),
                ["T1595"],
            ),
            CODE_ASSESSMENT_CONTRACT: (
                StrixContracts.code_contract_fields(),
                ["T1195.002"],
            ),
        }
        return prepare_contracts(
            [
                StrixContracts.build_contract(
                    cid,
                    fields_by_contract[cid][0],
                    en,
                    fr,
                    domains,
                    fields_by_contract[cid][1],
                )
                for cid, (en, fr, domains) in CONTRACT_LABELS.items()
            ]
        )
