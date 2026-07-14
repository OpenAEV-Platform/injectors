from typing import List

from pyoaev.contracts import ContractBuilder
from pyoaev.contracts.contract_config import (
    Contract,
    ContractCardinality,
    ContractConfig,
    ContractElement,
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
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_azure"

# Stable contract identifiers. Keep these constant across releases so the
# platform can match a stored inject back to its contract.
AZURE_DETONATE_CONTRACT = "6f2a1b4c-0a11-4c2e-9b3d-1e2f3a4b5c60"
ENTRA_DETONATE_CONTRACT = "6f2a1b4c-0a11-4c2e-9b3d-1e2f3a4b5c61"

# Curated subset of the Stratus Red Team catalog. This is a convenience list;
# the exact, authoritative catalog is `stratus list --platform azure`, and any
# id can be supplied through the "custom technique id" field.
AZURE_TECHNIQUES = {
    "azure.execution.vm-run-command": "Execution - Run command on Virtual Machine",
    "azure.exfiltration.disk-export": "Exfiltration - Export disk through SAS URL",
    "azure.persistence.create-bastion-shareable-link": (
        "Persistence - Create a Bastion shareable link"
    ),
}

ENTRA_TECHNIQUES = {
    "entra-id.persistence.new-application-credentials": (
        "Persistence - Add credentials to an application"
    ),
    "entra-id.persistence.guest-user": "Persistence - Invite an external guest user",
}


class AzureContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Azure + Entra ID",
                SupportedLanguage.fr: "Azure + Entra ID",
            },
            color_dark="#0078d4",
            color_light="#0078d4",
            expose=True,
        )

        tenant_id = ContractText(
            key="azure_tenant_id",
            label="Azure Tenant ID",
            mandatory=True,
        )
        subscription_id = ContractText(
            key="azure_subscription_id",
            label="Azure Subscription ID",
            mandatory=True,
        )
        client_id = ContractText(
            key="azure_client_id",
            label="Service Principal Client ID",
            mandatory=True,
        )
        client_secret = ContractText(
            key="azure_client_secret",
            label="Service Principal Client Secret",
            mandatory=True,
        )
        custom_technique = ContractText(
            key="custom_technique_id",
            label="Custom Stratus technique id (overrides the selection above)",
            mandatory=False,
        )

        expectations = ContractExpectations(
            key="expectations",
            label="Expectations",
            mandatory=False,
            cardinality=ContractCardinality.Multiple,
            predefinedExpectations=[
                Expectation(
                    expectation_type=ExpectationType.detection,
                    expectation_name="Detection",
                    expectation_description="",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
                Expectation(
                    expectation_type=ExpectationType.prevention,
                    expectation_name="Prevention",
                    expectation_description="",
                    expectation_score=100,
                    expectation_expectation_group=False,
                ),
            ],
        )

        output_technique = ContractOutputElement(
            type=ContractOutputType.Text,
            field="technique",
            isMultiple=False,
            isFindingCompatible=False,
            labels=["azure", "stratus", "technique"],
        )

        def technique_field(choices) -> ContractSelect:
            default = [next(iter(choices))]
            return ContractSelect(
                key="technique_id",
                label="Stratus technique",
                defaultValue=default,
                mandatory=True,
                choices=choices,
            )

        def make_fields(choices) -> List[ContractElement]:
            return (
                ContractBuilder()
                .add_fields(
                    [
                        tenant_id,
                        subscription_id,
                        client_id,
                        client_secret,
                        technique_field(choices),
                        custom_technique,
                        expectations,
                    ]
                )
                .build_fields()
            )

        azure_contract = Contract(
            contract_id=AZURE_DETONATE_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Azure - Detonate Stratus technique",
                SupportedLanguage.fr: "Azure - Détoner une technique Stratus",
            },
            fields=make_fields(AZURE_TECHNIQUES),
            outputs=ContractBuilder().add_outputs([output_technique]).build_outputs(),
            manual=False,
            domains=[SecurityDomains.CLOUD.value],
        )

        entra_contract = Contract(
            contract_id=ENTRA_DETONATE_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Entra ID - Detonate Stratus technique",
                SupportedLanguage.fr: "Entra ID - Détoner une technique Stratus",
            },
            fields=make_fields(ENTRA_TECHNIQUES),
            outputs=ContractBuilder().add_outputs([output_technique]).build_outputs(),
            manual=False,
            domains=[SecurityDomains.CLOUD.value],
        )

        return prepare_contracts([azure_contract, entra_contract])
