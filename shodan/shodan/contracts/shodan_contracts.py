from dataclasses import dataclass
from enum import Enum, StrEnum

from pyoaev.contracts.contract_config import (
    Contract,
    ContractAsset,
    ContractAssetGroup,
    ContractCardinality,
    ContractCheckbox,
    ContractConfig,
    ContractElement,
    ContractExpectations,
    ContractOutputElement,
    ContractOutputType,
    ContractSelect,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)

from shodan.contracts import (
    CloudProviderAssetDiscovery,
    CriticalPortsAndExposedAdminInterface,
    CustomQuery,
    CVEEnumeration,
    CVESpecificWatchlist,
    DomainDiscovery,
    HostEnumeration,
)
from shodan.models import ConfigLoader

TYPE = "openaev_shodan"


class InjectorKey(StrEnum):
    TARGETS_KEY = "targets"
    TARGET_SELECTOR_KEY = "target_selector"
    TARGET_PROPERTY_SELECTOR_KEY = "target_property_selector"
    AUTO_CREATE_ASSETS = "auto_create_assets"
    EXPECTATIONS_KEY = "expectations"


class ShodanContractId(StrEnum):
    CLOUD_PROVIDER_ASSET_DISCOVERY = "1887b988-1553-4e46-bac1-ceeee0483f3a"
    CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE = "5349febd-ec73-408b-aa61-24a86a1ba0a7"
    CUSTOM_QUERY = "c7640b4c-8a12-458a-b761-6a1287501a58"
    CVE_ENUMERATION = "8cdccd58-78ed-4e17-be2e-7683ec611569"
    CVE_SPECIFIC_WATCHLIST = "462087b4-8012-4e21-9575-b9c854ef5811"
    DOMAIN_DISCOVERY = "faf73809-1128-4192-aa90-a08828f8ace5"
    HOST_ENUMERATION = "dc6b8b73-09dd-4388-b7cc-108bf16d26cd"


@dataclass
class FieldDefinition:
    name: str
    target: str | list[str]
    label: str
    mandatory: bool = False


class TypeOfFields(Enum):
    ASSETS = FieldDefinition(
        name="field_assets",
        target="assets",
        label="Targeted assets",
    )
    ASSET_GROUPS = FieldDefinition(
        name="field_asset_groups",
        target="asset-groups",
        label="Targeted asset groups",
    )
    ASSETS_PROPERTY = FieldDefinition(
        name="field_assets_property",
        target=["assets", "asset-groups"],
        label="Targeted assets property",
    )


@dataclass
class SelectorFieldDefinition:
    key: str
    label: str


class TargetSelectorField(Enum):
    ASSETS = SelectorFieldDefinition(
        key="assets",
        label="Assets",
    )
    ASSET_GROUPS = SelectorFieldDefinition(
        key="asset-groups",
        label="Asset groups",
    )
    MANUAL = SelectorFieldDefinition(
        key="manual",
        label="Manual",
    )

    @property
    def key(self) -> str:
        return self.value.key

    @property
    def label(self) -> str:
        return self.value.label


class TargetProperty(Enum):
    AUTOMATIC = "Automatic"
    HOSTNAME = "Hostname"
    SEEN_IP = "Seen IP"
    LOCAL_IP = "Local IP (first)"

    @staticmethod
    def default_value(value: str = "automatic"):
        return value.lower()


class ShodanContracts:
    def __init__(self, config: ConfigLoader):
        # Load configuration file
        self.config = config

    # -- CONFIG --
    @staticmethod
    def _base_contract_config():
        return ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Shodan",
                SupportedLanguage.fr: "Shodan",
            },
            color_dark="#ff5722",
            color_light="#ff5722",
            expose=True,
        )

    # -- BUILDER CONTRACT FIELDS --
    @staticmethod
    def _build_target_selector(selector_default_value: str) -> ContractSelect:

        prefix = "only_"

        choices = {
            item_selector.key: item_selector.label
            for item_selector in TargetSelectorField
        }
        effective_default = selector_default_value
        default_start_with_only = selector_default_value.startswith(prefix)

        if default_start_with_only:
            effective_default = selector_default_value.removeprefix(prefix)
            choices = {effective_default: choices[effective_default]}

        return ContractSelect(
            key=InjectorKey.TARGET_SELECTOR_KEY,
            label="Type of targets",
            defaultValue=[effective_default],
            mandatory=True,
            choices=choices,
        )

    @staticmethod
    def _build_field(field_type: TypeOfFields) -> ContractElement:

        builder_contract_fields_mapping = {
            "field_assets": lambda **kwargs: ContractAsset(
                cardinality=ContractCardinality.Multiple, **kwargs
            ),
            "field_asset_groups": lambda **kwargs: ContractAssetGroup(
                cardinality=ContractCardinality.Multiple, **kwargs
            ),
            "field_assets_property": lambda **kwargs: ContractSelect(
                key=InjectorKey.TARGET_PROPERTY_SELECTOR_KEY,
                defaultValue=[TargetProperty.default_value()],
                choices={
                    item_property.name.lower(): item_property.value
                    for item_property in TargetProperty
                },
                **kwargs
            ),
        }

        field_type_config = field_type.value
        builder = builder_contract_fields_mapping[field_type_config.name]

        return builder(
            label=field_type_config.label,
            mandatory=field_type_config.mandatory,
            mandatoryConditionFields=[InjectorKey.TARGET_SELECTOR_KEY],
            mandatoryConditionValues={
                InjectorKey.TARGET_SELECTOR_KEY: field_type_config.target
            },
            visibleConditionFields=[InjectorKey.TARGET_SELECTOR_KEY],
            visibleConditionValues={
                InjectorKey.TARGET_SELECTOR_KEY: field_type_config.target
            },
        )

    @staticmethod
    def _build_auto_create_assets_checkbox() -> ContractElement:
        return ContractCheckbox(
            key=InjectorKey.AUTO_CREATE_ASSETS,
            label="Auto-Create assets",
            defaultValue=False,
            mandatory=False,
        )

    @staticmethod
    def _build_expectations():
        return ContractExpectations(
            key=InjectorKey.EXPECTATIONS_KEY,
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

    def _base_fields(self, selector_default_value: str) -> list[ContractElement]:

        # Build Target Selector (Assets, Asset Groups, Manual)
        target_selector = self._build_target_selector(selector_default_value)

        # Build all fields
        target_assets = self._build_field(TypeOfFields.ASSETS)
        target_asset_groups = self._build_field(TypeOfFields.ASSET_GROUPS)
        target_assets_property = self._build_field(TypeOfFields.ASSETS_PROPERTY)

        # Build Checkbox Auto-Create Assets
        checkbox_auto_create_assets = self._build_auto_create_assets_checkbox()

        # Build expectations
        expectations = self._build_expectations()

        return [
            target_selector,
            target_assets,
            target_asset_groups,
            target_assets_property,
            checkbox_auto_create_assets,
            expectations,
        ]

    # -- OUTPUTS --
    @staticmethod
    def _base_outputs():
        # output_assets = ContractOutputElement(
        #     type=ContractOutputType.ASSET,
        #     field="found_assets",
        #     isMultiple=True,
        #     isFindingCompatible=False,
        #     labels=["shodan"],
        # )
        return []

    def _build_contract(
        self,
        contract_id: str,
        contract_cls: (
            CloudProviderAssetDiscovery
            | CriticalPortsAndExposedAdminInterface
            | CustomQuery
            | CVEEnumeration
            | CVESpecificWatchlist
            | DomainDiscovery
            | HostEnumeration
        ),
        contract_selector_default: str,
    ) -> Contract:
        return contract_cls.contract(
            contract_id=contract_id,
            contract_config=self._base_contract_config(),
            contract_with_specific_fields=contract_cls.contract_with_specific_fields(
                base_fields=self._base_fields(contract_selector_default),
                source_selector_key=InjectorKey.TARGET_SELECTOR_KEY,
                target_selector_field=TargetSelectorField.MANUAL.key,
            ),
            contract_with_specific_outputs=contract_cls.contract_with_specific_outputs(
                self._base_outputs()
            ),
        )

    def contracts(self):

        selector_default = TargetSelectorField.ASSET_GROUPS.key

        shodan_contract_definitions = [
            (
                ShodanContractId.CLOUD_PROVIDER_ASSET_DISCOVERY,
                CloudProviderAssetDiscovery,
                selector_default,
            ),
            (
                ShodanContractId.CRITICAL_PORTS_AND_EXPOSED_ADMIN_INTERFACE,
                CriticalPortsAndExposedAdminInterface,
                selector_default,
            ),
            (ShodanContractId.CUSTOM_QUERY, CustomQuery, "only_manual"),
            (ShodanContractId.CVE_ENUMERATION, CVEEnumeration, selector_default),
            (
                ShodanContractId.CVE_SPECIFIC_WATCHLIST,
                CVESpecificWatchlist,
                selector_default,
            ),
            (ShodanContractId.DOMAIN_DISCOVERY, DomainDiscovery, selector_default),
            (ShodanContractId.HOST_ENUMERATION, HostEnumeration, selector_default),
        ]

        contracts = [
            self._build_contract(contract_id, contract_cls, contract_selector_default)
            for contract_id, contract_cls, contract_selector_default in shodan_contract_definitions
        ]

        return {"data": prepare_contracts(contracts)}
