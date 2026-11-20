from unittest import TestCase
from unittest.mock import MagicMock

from injector_common.constants import (
    ASSETS_KEY_RABBITMQ,
    TARGET_PROPERTY_SELECTOR_KEY,
    TARGET_SELECTOR_KEY,
    TARGETS_KEY,
)
from injector_common.targets import (
    TargetExtractionResult,
    TargetResolution,
    Targets,
)


class CommonTargetsTest(TestCase):

    def setUp(self):
        self.asset_hostname = {
            "asset_id": "a1",
            "asset_hostname": "host.local",
            "asset_ips": ["10.0.0.1"],
            "asset_agents": False,  # agentless
        }
        self.asset_local_ip = {
            "asset_id": "a2",
            "asset_hostname": None,
            "asset_ips": ["10.0.0.2"],
            "asset_agents": True,  # has agent
        }
        self.empty_asset_ips = {
            "asset_id": "a3",
            "asset_hostname": None,
            "asset_ips": [],  # no ips
            "asset_agents": True,
        }
        self.asset_seen_and_local_ip = {
            "asset_id": "a4",
            "asset_hostname": None,
            "asset_ips": ["192.168.56.11"],  # local address
            "asset_seen_ip": "74.234.220.121",  # what the endpoint screen shows
            "asset_agents": True,
        }
        self.asset_loopback_seen_ip = {
            "asset_id": "a5",
            "asset_hostname": None,
            "asset_ips": ["10.0.0.5"],
            "asset_seen_ip": "127.0.0.1",  # unusable, must fall back
            "asset_agents": True,
        }
        self.asset_none_seen_ip = {
            "asset_id": "a6",
            "asset_hostname": None,
            "asset_ips": ["10.0.0.6"],
            "asset_seen_ip": None,  # optional field, explicitly absent
            "asset_agents": True,
        }

        self.mock_helper = MagicMock()

    # ---------- extract_property_target_value ----------

    def test_extract_property_target_value_hostname(self):
        target, asset_id = Targets._extract_property_target_value(self.asset_hostname)
        self.assertEqual(target, "host.local")
        self.assertEqual(asset_id, "a1")

    def test_extract_property_target_value_local_ip(self):
        target, asset_id = Targets._extract_property_target_value(self.asset_local_ip)
        self.assertEqual(target, "10.0.0.2")
        self.assertEqual(asset_id, "a2")

    def test_extract_property_target_value_no_valid_field(self):
        target = Targets._extract_property_target_value(self.empty_asset_ips)
        self.assertIsNone(target)

    def test_extract_property_target_value_prefers_seen_ip_over_local_ip(self):
        # The endpoint screen shows the seen IP, so automatic targeting must use it rather
        # than a local address the operator never saw.
        target, asset_id = Targets._extract_property_target_value(
            self.asset_seen_and_local_ip
        )
        self.assertEqual(target, "74.234.220.121")
        self.assertEqual(asset_id, "a4")

    def test_extract_property_target_value_falls_back_when_seen_ip_unusable(self):
        target, asset_id = Targets._extract_property_target_value(
            self.asset_loopback_seen_ip
        )
        self.assertEqual(target, "10.0.0.5")
        self.assertEqual(asset_id, "a5")

    def test_extract_property_target_value_falls_back_when_seen_ip_is_none(self):
        # asset_seen_ip is optional and may be missing or None. That must not raise
        # and must fall back to the first valid local IP.
        target, asset_id = Targets._extract_property_target_value(
            self.asset_none_seen_ip
        )
        self.assertEqual(target, "10.0.0.6")
        self.assertEqual(asset_id, "a6")

    def test_is_valid_ip_handles_none_and_invalid(self):
        # Guards is_valid_ip against optional/None payload fields (asset_seen_ip)
        # so automatic targeting never raises on assets without a seen IP.
        self.assertFalse(Targets._is_valid_ip(None))
        self.assertFalse(Targets._is_valid_ip(""))
        self.assertFalse(Targets._is_valid_ip("not-an-ip"))
        self.assertFalse(Targets._is_valid_ip("127.0.0.1"))
        self.assertTrue(Targets._is_valid_ip("74.234.220.121"))

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

    # ---------- extract_target_meta ----------

    def test_given_message_with_asset_groups_should_read_group_members_from_message(
        self,
    ):
        # Arrange: one member with an agent and one member without a usable target
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "asset-groups",
                    TARGET_PROPERTY_SELECTOR_KEY: "automatic",
                }
            },
            ASSETS_KEY_RABBITMQ: [
                {**self.asset_local_ip, "asset_agents": [{"agent_id": "ag2"}]},
                self.empty_asset_ips,
            ],
        }

        # Act
        result = Targets.extract_targets(
            "asset-groups", "automatic", data, self.mock_helper
        )
        metas = Targets.extract_target_meta(
            "asset-groups", "automatic", data, self.mock_helper
        )

        # Assert: the member is scanned once, with a single TargetMeta
        self.assertEqual(result.targets, ["10.0.0.2"])
        self.assertEqual(
            [(meta.asset_id, meta.agent_id) for meta in metas],
            [("a2", "ag2")],
        )

    def test_given_message_with_asset_groups_should_align_meta_with_targets_in_assets_mode(
        self,
    ):
        # Arrange
        data = {
            "injection": {
                "inject_content": {
                    TARGET_SELECTOR_KEY: "assets",
                    TARGET_PROPERTY_SELECTOR_KEY: "local_ip",
                }
            },
            ASSETS_KEY_RABBITMQ: [
                {**self.empty_asset_ips, "asset_agents": []},
                {**self.asset_local_ip, "asset_agents": []},
            ],
        }

        # Act
        result = Targets.extract_targets("assets", "local_ip", data, self.mock_helper)
        metas = Targets.extract_target_meta(
            "assets", "local_ip", data, self.mock_helper
        )

        # Assert: the asset without a local IP is skipped in both lists
        self.assertEqual(result.targets, ["10.0.0.2"])
        self.assertEqual([meta.asset_id for meta in metas], ["a2"])
        self.assertIsNone(metas[0].agent_id)

    # ---------- automatic resolution, visible per asset ----------

    def test_automatic_order_records_the_field_used(self):
        agentless = {
            "asset_id": "a1",
            "asset_name": "web-01",
            "asset_hostname": "worker-01.example.com",
            "asset_seen_ip": "203.0.113.9",
            "asset_agents": [],
        }
        cases = [
            (agentless, "worker-01.example.com", "hostname"),
            (self.asset_seen_and_local_ip, "74.234.220.121", "seen_ip"),
            (self.asset_loopback_seen_ip, "10.0.0.5", "local_ip"),
        ]
        for asset, value, field_used in cases:
            resolution = Targets._resolve_target(asset, "automatic")
            self.assertEqual(resolution.target, value)
            self.assertEqual(resolution.value_property, field_used)
            self.assertEqual(resolution.selector, "automatic")
        self.assertIsNone(Targets._resolve_target(self.empty_asset_ips, "automatic"))

    def test_resolution_describe(self):
        agentless = Targets._resolve_target(
            {
                "asset_id": "a1",
                "asset_name": "web-01",
                "asset_hostname": "worker-01.example.com",
                "asset_agents": [],
            },
            "automatic",
        )
        self.assertEqual(
            agentless.describe(),
            "asset web-01: hostname worker-01.example.com (automatic, agentless)",
        )
        seen = Targets._resolve_target(self.asset_seen_and_local_ip, "automatic")
        self.assertEqual(
            seen.describe(), "asset a4: seen IP 74.234.220.121 (automatic)"
        )

    def test_extract_targets_keeps_resolutions_and_message_shows_them(self):
        data = {
            "injection": {"inject_content": {}},
            ASSETS_KEY_RABBITMQ: [self.asset_hostname, self.asset_seen_and_local_ip],
        }
        result = Targets.extract_targets("assets", "automatic", data, self.mock_helper)
        self.assertEqual(
            [(r.target, r.value_property) for r in result.resolutions],
            [("host.local", "hostname"), ("74.234.220.121", "seen_ip")],
        )
        message = Targets.build_execution_message(
            "assets", data, ["nmap", "-sS"], target_results=result
        )
        self.assertEqual(
            message,
            "nmap -sS\nResolved targets:\n"
            "- asset a1: hostname host.local (automatic, agentless)\n"
            "- asset a4: seen IP 74.234.220.121 (automatic)",
        )

    def test_message_unchanged_for_explicit_properties(self):
        data = {
            "injection": {"inject_content": {}},
            ASSETS_KEY_RABBITMQ: [self.asset_local_ip],
        }
        result = Targets.extract_targets("assets", "local_ip", data, self.mock_helper)
        self.assertEqual(
            Targets.build_execution_message(
                "assets", data, ["nmap"], target_results=result
            ),
            "nmap",
        )

    def test_missed_targets_by_value(self):
        result = TargetExtractionResult(
            targets=["Missing.Invalid", "10.0.0.2", "10.0.0.3"],
            ip_to_asset_id_map={},
            resolutions=[
                TargetResolution("Missing.Invalid", "a1", "web-01"),
                TargetResolution("10.0.0.2", "a2"),
                TargetResolution("10.0.0.3", "a3"),
            ],
        )
        missed = Targets.missed_targets(result, ["10.0.0.2"], ["missing.invalid"])
        self.assertEqual(
            [m.describe() for m in missed],
            [
                "Missing.Invalid (asset web-01): not scanned, hostname did not resolve",
                "10.0.0.3 (asset a3): not scanned, no result returned by the scan",
            ],
        )

    def test_missed_targets_for_manual_targets(self):
        result = TargetExtractionResult(
            targets=["a.invalid", "10.0.0.1"], ip_to_asset_id_map={}
        )
        missed = Targets.missed_targets(result, ["10.0.0.1"])
        self.assertEqual(
            [m.describe() for m in missed],
            ["a.invalid: not scanned, hostname did not resolve"],
        )
