from unittest import TestCase

from gcp_injector.contracts_gcp import GCP_DETONATE_CONTRACT, GcpContracts
from gcp_injector.openaev_gcp import OpenAEVGcp


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = GcpContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], GCP_DETONATE_CONTRACT)


class TechniqueResolverTest(TestCase):
    def test_custom_overrides(self):
        content = {
            "custom_technique_id": "gcp.persistence.custom",
            "technique_id": ["gcp.exfiltration.share-compute-disk"],
        }
        self.assertEqual(
            OpenAEVGcp._resolve_technique(content), "gcp.persistence.custom"
        )

    def test_list_selection(self):
        content = {"technique_id": ["gcp.exfiltration.share-compute-disk"]}
        self.assertEqual(
            OpenAEVGcp._resolve_technique(content),
            "gcp.exfiltration.share-compute-disk",
        )

    def test_none(self):
        self.assertIsNone(OpenAEVGcp._resolve_technique({}))
