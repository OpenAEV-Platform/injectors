import json
import unittest

from dns_enum.contracts.dns_enum_constants import DNS_ENUMERATION_CONTRACT
from dns_enum.contracts.dns_enum_contracts import DnsEnumContracts


class TestDnsEnumContracts(unittest.TestCase):
    def test_contract_shape(self):
        contracts = DnsEnumContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], DNS_ENUMERATION_CONTRACT)
        content = json.loads(contracts[0]["contract_content"])
        keys = [field["key"] for field in content["fields"]]
        for key in [
            "domains",
            "record_types",
            "brute_force",
            "create_endpoints",
            "expectations",
        ]:
            self.assertIn(key, keys)
        create = next(f for f in content["fields"] if f["key"] == "create_endpoints")
        self.assertFalse(create["defaultValue"])
        brute = next(f for f in content["fields"] if f["key"] == "brute_force")
        self.assertFalse(brute["defaultValue"])
        classify = next(f for f in content["fields"] if f["key"] == "classify_assets")
        self.assertTrue(classify["defaultValue"])

    def test_asset_group_and_tags_pickers(self):
        content = json.loads(DnsEnumContracts.build_contract()[0]["contract_content"])
        fields = {f["key"]: f for f in content["fields"]}
        group = fields["asset_group_id"]
        self.assertEqual(group["type"], "asset-group-reference")
        self.assertEqual(group["cardinality"], "1")
        self.assertFalse(group["mandatory"])
        self.assertEqual(group["visibleConditionFields"], ["create_endpoints"])
        tags = fields["endpoint_tag"]
        self.assertEqual(tags["type"], "tags")
        self.assertEqual(tags["cardinality"], "n")
        self.assertFalse(tags["mandatory"])
        # A tags field holds ids: no name as default value.
        self.assertEqual(tags["defaultValue"], [])

    def test_outputs(self):
        content = json.loads(DnsEnumContracts.build_contract()[0]["contract_content"])
        outputs = {o["field"]: o for o in content["outputs"]}
        self.assertTrue(outputs["discovered_hosts"]["isFindingCompatible"])
        self.assertTrue(outputs["ipv4"]["isFindingCompatible"])
        self.assertFalse(outputs["manual_targets"]["isFindingCompatible"])
        self.assertIn("expectation_signatures", outputs)
        self.assertIn("action_output", outputs)


if __name__ == "__main__":
    unittest.main()
