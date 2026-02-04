from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractSelect,
    ContractText,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.contracts.contract_utils import ContractCardinality
from pyoaev.security_domain.types import SecurityDomains

from injector_common.constants import (
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.targets import TargetProperty, target_property_choices_dict

CONTRACT_TYPE = "openaev_netexec"
CONTRACT_ID_SMB_AUTH = "b6b9b5c4-1a0e-4b3c-9a8a-netexec-smb-auth"


class NetExecContracts:

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
        ]

    @staticmethod
    def build() -> List[Contract]:
        # Contract configuration
        contract_config = ContractConfig(
            type=CONTRACT_TYPE,
            label={
                SupportedLanguage.en: "NetExec",
                SupportedLanguage.fr: "NetExec",
            },
            color_dark="#d32f2f",
            color_light="#ffcdd2",
            expose=True,
        )

        # Contract fields
        smb_auth_fields: List[ContractElement] = (
            ContractBuilder()
            .optional(
                ContractText(
                    key="username",
                    label="Username",
                )
            )
            .optional(
                ContractText(
                    key="password",
                    label="Password",
                )
            )
            .optional(
                ContractSelect(
                    key="options",
                    label="Options",
                    choices={
                        "--shares": "--shares",
                        "--pass-pol": "--pass-pol",
                        "--users": "--users",
                        "--groups": "--groups",
                        "--sessions": "--sessions",
                        "--loggedon-users": "--loggedon-users",
                    },
                ),
            )
            .add_fields(NetExecContracts.core_contract_fields())
            .build_fields()
        )

        smb_auth_contract = Contract(
            contract_id=CONTRACT_ID_SMB_AUTH,
            config=contract_config,
            label={
                SupportedLanguage.en: "NetExec - SMB authentication check",
                SupportedLanguage.fr: "NetExec - Vérification authentification SMB",
            },
            fields=smb_auth_fields,
            outputs=[],
            manual=False,
            domains=[
                SecurityDomains.ENDPOINT.value,
            ],
        )

        return prepare_contracts([smb_auth_contract])
