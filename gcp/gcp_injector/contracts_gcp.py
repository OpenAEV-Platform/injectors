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
    ContractTextArea,
    Expectation,
    ExpectationType,
    SupportedLanguage,
    prepare_contracts,
)
from pyoaev.security_domain.types import SecurityDomains

TYPE = "openaev_gcp"

GCP_DETONATE_CONTRACT = "7a3b2c5d-1b22-4d3f-8c4e-2f3a4b5c6d70"

# Convenience subset of `stratus list --platform gcp`; any id can be supplied
# through the custom technique field.
GCP_TECHNIQUES = {
    "gcp.exfiltration.share-compute-disk": (
        "Exfiltration - Share a Compute Disk with an external account"
    ),
    "gcp.exfiltration.share-compute-image": (
        "Exfiltration - Share a Compute Image with an external account"
    ),
    "gcp.persistence.create-admin-service-account": (
        "Persistence - Create an admin service account"
    ),
    "gcp.persistence.invite-external-user": "Persistence - Invite an external user",
}


class GcpContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Google Cloud Platform",
                SupportedLanguage.fr: "Google Cloud Platform",
            },
            color_dark="#1a73e8",
            color_light="#1a73e8",
            expose=True,
        )

        project_id = ContractText(
            key="gcp_project_id",
            label="GCP Project ID",
            mandatory=True,
        )
        service_account_key = ContractTextArea(
            key="gcp_service_account_key",
            label="Service Account key (JSON)",
            mandatory=True,
        )
        custom_technique = ContractText(
            key="custom_technique_id",
            label="Custom Stratus technique id (overrides the selection above)",
            mandatory=False,
        )
        technique = ContractSelect(
            key="technique_id",
            label="Stratus technique",
            defaultValue=[next(iter(GCP_TECHNIQUES))],
            mandatory=True,
            choices=GCP_TECHNIQUES,
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
            labels=["gcp", "stratus", "technique"],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields(
                [
                    project_id,
                    service_account_key,
                    technique,
                    custom_technique,
                    expectations,
                ]
            )
            .build_fields()
        )

        gcp_contract = Contract(
            contract_id=GCP_DETONATE_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "GCP - Detonate Stratus technique",
                SupportedLanguage.fr: "GCP - Détoner une technique Stratus",
            },
            fields=fields,
            outputs=ContractBuilder().add_outputs([output_technique]).build_outputs(),
            manual=False,
            domains=[SecurityDomains.CLOUD.value],
        )

        return prepare_contracts([gcp_contract])
