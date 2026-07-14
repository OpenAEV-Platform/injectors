from unittest import TestCase

from kubernetes_injector.contracts_kubernetes import (
    K8S_DETONATE_CONTRACT,
    KubernetesContracts,
)
from kubernetes_injector.openaev_kubernetes import OpenAEVKubernetes


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = KubernetesContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], K8S_DETONATE_CONTRACT)


class TechniqueResolverTest(TestCase):
    def test_custom_overrides(self):
        content = {
            "custom_technique_id": "k8s.persistence.custom",
            "technique_id": ["k8s.credential-access.dump-secrets"],
        }
        self.assertEqual(
            OpenAEVKubernetes._resolve_technique(content),
            "k8s.persistence.custom",
        )

    def test_none(self):
        self.assertIsNone(OpenAEVKubernetes._resolve_technique({}))

    def test_blank_custom_falls_back_to_selected(self):
        content = {
            "custom_technique_id": "   ",
            "technique_id": ["k8s.credential-access.dump-secrets"],
        }
        self.assertEqual(
            OpenAEVKubernetes._resolve_technique(content),
            "k8s.credential-access.dump-secrets",
        )

    def test_blank_selection_returns_none(self):
        content = {"custom_technique_id": "", "technique_id": ["  "]}
        self.assertIsNone(OpenAEVKubernetes._resolve_technique(content))
