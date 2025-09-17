from unittest import TestCase

from nuclei.nuclei_contracts.nuclei_constants import (
    ASSETS_KEY,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from nuclei.nuclei_contracts.nuclei_contracts import (
    NucleiContracts,
    TargetExtractionResult,
)


class NucleiExtractPropertyTargetValueTest(TestCase):

    def setUp(self):
        self.asset_hostname = {
            "asset_id": "a1",
            "endpoint_hostname": "host.local",
            "endpoint_ips": ["10.0.0.1"],
            "asset_agents": [],  # agentless
        }
        self.asset_with_agent_no_ips = {
            "asset_id": "a2",
            "endpoint_hostname": "host.nia.local",
            "endpoint_ips": [],
            "asset_agents": [{"agent_id": "x"}],  # has agent
        }
        self.asset_local_ip = {
            "asset_id": "a3",
            "endpoint_hostname": None,
            "endpoint_ips": ["10.0.0.3"],
            "asset_agents": [{"agent_id": "y"}],  # has agent
        }
        self.empty_asset_ips = {
            "asset_id": "a4",
            "endpoint_hostname": None,
            "endpoint_ips": [],  # no ips
            "asset_agents": [{"agent_id": "z"}],
        }

    # ---------- extract_property_target_value ----------

    def test_extract_property_target_value_hostname(self):
        target, asset_id = NucleiContracts.extract_property_target_value(
            self.asset_hostname
        )
        self.assertEqual(target, "host.local")
        self.assertEqual(asset_id, "a1")

    def test_extract_property_target_value_with_agent(self):
        target, asset_id = NucleiContracts.extract_property_target_value(
            self.asset_with_agent_no_ips
        )
        self.assertEqual(target, "host.nia.local")
        self.assertEqual(asset_id, "a2")

    def test_extract_property_target_value_local_ip(self):
        target, asset_id = NucleiContracts.extract_property_target_value(
            self.asset_local_ip
        )
        self.assertEqual(target, "10.0.0.3")
        self.assertEqual(asset_id, "a3")

    def test_extract_property_target_value_no_valid_field(self):
        target = NucleiContracts.extract_property_target_value(self.empty_asset_ips)
        self.assertIsNone(target)

        # ---------- extract_targets ----------

    def test_extract_targets_automatic(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "automatic",
                }
            },
            ASSETS_KEY: [
                self.asset_hostname,
                self.asset_with_agent_no_ips,
                self.asset_local_ip,
            ],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertCountEqual(
            result.targets, ["host.local", "host.nia.local", "10.0.0.3"]
        )
        self.assertEqual(len(result.ip_to_asset_id_map), 3)

    def test_extract_targets_local_ip(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "local_ip",
                }
            },
            ASSETS_KEY: [self.asset_local_ip],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["10.0.0.3"])
        self.assertEqual(result.ip_to_asset_id_map, {"10.0.0.3": "a3"})

    def test_extract_targets_local_ip_no_ips(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "local_ip",
                }
            },
            ASSETS_KEY: [self.empty_asset_ips],
        }
        with self.assertRaises(ValueError):
            NucleiContracts.extract_targets(data)

    def test_extract_targets_hostname(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "hostname",
                }
            },
            ASSETS_KEY: [self.asset_hostname],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["host.local"])
        self.assertEqual(result.ip_to_asset_id_map, {"host.local": "a1"})

    def test_extract_targets_manual(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "manual",
                    TARGETS_KEY: "titi.com, toto.com , ,foo.com",
                }
            },
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["titi.com", "toto.com", "foo.com"])
        self.assertEqual(result.ip_to_asset_id_map, {})

    def test_extract_targets_no_targets(self):
        data = {"injection": {"inject_content": {TARGET_SELECTOR_KEY: "unknown"}}}
        with self.assertRaises(ValueError):
            NucleiContracts.extract_targets(data)
