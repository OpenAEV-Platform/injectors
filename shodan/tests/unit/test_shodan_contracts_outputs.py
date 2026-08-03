import unittest

from pyoaev.contracts.contract_config import ContractOutputType

from shodan.contracts.shodan_contracts import ShodanContracts


class TestShodanContractOutputs(unittest.TestCase):
    """The Shodan contracts must expose IPv4 / Port / CVE finding-compatible
    outputs so discovered exposure can feed the AI attack path, while assets
    stay a non-finding output."""

    def setUp(self):
        self.outputs = {out.field: out for out in ShodanContracts._base_outputs()}

    def test_declares_finding_compatible_hosts_ports_cves(self):
        expected_types = {
            "hosts": ContractOutputType.IPv4,
            "ports": ContractOutputType.Port,
            "cves": ContractOutputType.CVE,
        }
        for field, output_type in expected_types.items():
            self.assertIn(field, self.outputs)
            self.assertEqual(self.outputs[field].type, output_type)
            self.assertTrue(self.outputs[field].isFindingCompatible)
            self.assertTrue(self.outputs[field].isMultiple)

    def test_found_assets_is_not_finding_compatible(self):
        self.assertIn("found_assets", self.outputs)
        self.assertFalse(self.outputs["found_assets"].isFindingCompatible)
