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

TYPE = "openaev_kubernetes"

K8S_DETONATE_CONTRACT = "8b4c3d6e-2c33-4e40-9d5f-3a4b5c6d7e80"

# Convenience subset of `stratus list --platform kubernetes`.
K8S_TECHNIQUES = {
    "k8s.persistence.create-admin-clusterrole": (
        "Persistence - Create an admin ClusterRole"
    ),
    "k8s.privilege-escalation.hostpath-volume": (
        "Privilege Escalation - Mount a sensitive host path"
    ),
    "k8s.credential-access.dump-secrets": "Credential Access - Dump all secrets",
}


class KubernetesContracts:
    @staticmethod
    def build_contract():
        contract_config = ContractConfig(
            type=TYPE,
            label={
                SupportedLanguage.en: "Kubernetes",
                SupportedLanguage.fr: "Kubernetes",
            },
            color_dark="#326ce5",
            color_light="#326ce5",
            expose=True,
        )

        kubeconfig = ContractTextArea(
            key="kubeconfig",
            label="Kubeconfig (YAML)",
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
            defaultValue=[next(iter(K8S_TECHNIQUES))],
            mandatory=True,
            choices=K8S_TECHNIQUES,
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
            labels=["kubernetes", "stratus", "technique"],
        )

        fields: List[ContractElement] = (
            ContractBuilder()
            .add_fields([kubeconfig, technique, custom_technique, expectations])
            .build_fields()
        )

        k8s_contract = Contract(
            contract_id=K8S_DETONATE_CONTRACT,
            config=contract_config,
            label={
                SupportedLanguage.en: "Kubernetes - Detonate Stratus technique",
                SupportedLanguage.fr: "Kubernetes - Détoner une technique Stratus",
            },
            fields=fields,
            outputs=ContractBuilder().add_outputs([output_technique]).build_outputs(),
            manual=False,
            domains=[SecurityDomains.CLOUD.value],
        )

        return prepare_contracts([k8s_contract])
