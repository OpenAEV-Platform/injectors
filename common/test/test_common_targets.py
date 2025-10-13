from unittest import TestCase
from unittest.mock import MagicMock

from common.common.constants import (
    ASSETS_KEY_RABBITMQ,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from common.common.targets import Targets


class CommonTargetsTest(TestCase):

    def setUp(self):
        self.asset_hostname = {
            "asset_id": "a1",
            "endpoint_hostname": "host.local",
            "endpoint_ips": ["10.0.0.1"],
            "asset_agents": False,  # agentless
        }
        self.asset_local_ip = {
            "asset_id": "a2",
            "endpoint_hostname": None,
            "endpoint_ips": ["10.0.0.2"],
            "asset_agents": True,  # has agent
        }
        self.empty_asset_ips = {
            "asset_id": "a3",
            "endpoint_hostname": None,
            "endpoint_ips": [],  # no ips
            "asset_agents": True,
        }

        self.mock_helper = MagicMock()

    # ---------- extract_property_target_value ----------

    def test_extract_property_target_value_hostname(self):
        target, asset_id = Targets.extract_property_target_value(self.asset_hostname)
        self.assertEqual(target, "host.local")
        self.assertEqual(asset_id, "a1")

    def test_extract_property_target_value_local_ip(self):
        target, asset_id = Targets.extract_property_target_value(self.asset_local_ip)
        self.assertEqual(target, "10.0.0.2")
        self.assertEqual(asset_id, "a2")

    def test_extract_property_target_value_no_valid_field(self):
        target = Targets.extract_property_target_value(self.empty_asset_ips)
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
            ASSETS_KEY_RABBITMQ: [
                self.asset_hostname,
                self.asset_local_ip,
            ],
        }
        result = Targets.extract_targets(
            "assets", "automatic", data, helper=self.mock_helper
        )
        self.assertCountEqual(result.targets, ["host.local", "10.0.0.2"])
        self.assertEqual(len(result.ip_to_asset_id_map), 2)

    def test_extract_targets_local_ip(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "local_ip",
                }
            },
            ASSETS_KEY_RABBITMQ: [self.asset_local_ip],
        }
        result = Targets.extract_targets(
            "assets", "local_ip", data, helper=self.mock_helper
        )
        self.assertEqual(result.targets, ["10.0.0.2"])
        self.assertEqual(result.ip_to_asset_id_map, {"10.0.0.2": "a2"})

    def test_extract_targets_local_ip_no_ips(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "local_ip",
                }
            },
            ASSETS_KEY_RABBITMQ: [self.empty_asset_ips],
        }
        result = Targets.extract_targets(
            "assets", "local_ip", data, helper=self.mock_helper
        )
        self.assertEqual(result.targets, [])

    def test_extract_targets_hostname(self):
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "hostname",
                }
            },
            ASSETS_KEY_RABBITMQ: [self.asset_hostname],
        }
        result = Targets.extract_targets(
            "assets", "hostname", data, helper=self.mock_helper
        )
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
        result = Targets.extract_targets("manual", None, data, helper=self.mock_helper)
        self.assertEqual(result.targets, ["titi.com", "toto.com", "foo.com"])
        self.assertEqual(result.ip_to_asset_id_map, {})

    def test_extract_targets_no_targets(self):
        data = {"injection": {"inject_content": {TARGET_SELECTOR_KEY: "unknown"}}}
        with self.assertRaises(ValueError):
            Targets.extract_targets("unknown", None, data, helper=self.mock_helper)
