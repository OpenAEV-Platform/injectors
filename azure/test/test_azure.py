from unittest import TestCase

from azure_injector.contracts_azure import (
    AZURE_DETONATE_CONTRACT,
    ENTRA_DETONATE_CONTRACT,
    AzureContracts,
)
from azure_injector.openaev_azure import OpenAEVAzure


class ContractsTest(TestCase):
    def test_build_contract_returns_two_contracts(self):
        contracts = AzureContracts.build_contract()
        ids = {c["contract_id"] for c in contracts}
        self.assertEqual(ids, {AZURE_DETONATE_CONTRACT, ENTRA_DETONATE_CONTRACT})

    def test_contracts_are_tagged_cloud_domain(self):
        for contract in AzureContracts.build_contract():
            self.assertTrue(contract["contract_domains"])


class TechniqueResolverTest(TestCase):
    def test_custom_technique_overrides_selection(self):
        content = {
            "custom_technique_id": "azure.execution.custom",
            "technique_id": ["azure.exfiltration.disk-export"],
        }
        self.assertEqual(
            OpenAEVAzure._resolve_technique(content), "azure.execution.custom"
        )

    def test_selection_as_list(self):
        content = {"technique_id": ["azure.exfiltration.disk-export"]}
        self.assertEqual(
            OpenAEVAzure._resolve_technique(content),
            "azure.exfiltration.disk-export",
        )

    def test_selection_as_string(self):
        content = {"technique_id": "azure.execution.vm-run-command"}
        self.assertEqual(
            OpenAEVAzure._resolve_technique(content),
            "azure.execution.vm-run-command",
        )

    def test_no_technique_returns_none(self):
        self.assertIsNone(OpenAEVAzure._resolve_technique({}))
