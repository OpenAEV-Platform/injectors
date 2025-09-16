from unittest import TestCase

from nuclei.nuclei_contracts.nuclei_contracts import NucleiContracts, TargetExtractionResult

TARGET_SELECTOR_KEY = "target_selector"
TARGET_PROPERTY_SELECTOR_KEY = "target_property_selector"
TARGETS_KEY = "targets"
ASSETS_KEY = "assets"

class NucleiExtractPropertyTargetValueTest(TestCase):

    def setUp(self):
        self.asset_hostname = {
            "asset_id": "a1",
            "endpoint_hostname": "host.local",
            "endpoint_seen_ip": "1.1.1.1",
            "endpoint_ips": ["10.0.0.1"],
        }
        self.asset_seen_ip = {
            "asset_id": "a2",
            "endpoint_hostname": None,
            "endpoint_seen_ip": "2.2.2.2",
            "endpoint_ips": ["10.0.0.2"],
        }
        self.asset_local_ip = {
            "asset_id": "a3",
            "endpoint_hostname": None,
            "endpoint_seen_ip": None,
            "endpoint_ips": ["10.0.0.3"],
        }
        self.empty_asset_ips = {
            "asset_id": "a4",
            "endpoint_hostname": None,
            "endpoint_seen_ip": None,
            "endpoint_ips": [],
        }
    
    def test_extract_property_target_value_hostname(self):
        target, asset_id = NucleiContracts.extract_property_target_value(self.asset_hostname)
        self.assertEqual(target, "host.local")
        self.assertEqual(asset_id, "a1")
    
    def test_extract_property_target_value_seen_ip(self):
        asset = dict(self.asset_seen_ip)
        target, asset_id = NucleiContracts.extract_property_target_value(asset)
        self.assertEqual(target, "2.2.2.2")
        self.assertEqual(asset_id, "a2")
    
    def test_extract_property_target_value_local_ip(self):
        asset = dict(self.asset_local_ip)
        target, asset_id = NucleiContracts.extract_property_target_value(asset)
        self.assertEqual(target, "10.0.0.3")
        self.assertEqual(asset_id, "a3")
    
    def test_extract_property_target_value_no_valid_field(self):
        with self.assertRaises(ValueError):
            NucleiContracts.extract_property_target_value(self.empty_asset_ips)
    
    # ---------- extract_targets ----------
    
    def test_extract_targets_automatic(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "assets", TARGET_PROPERTY_SELECTOR_KEY: "automatic"}},
            ASSETS_KEY: [self.asset_hostname, self.asset_seen_ip, self.asset_local_ip],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertIsInstance(result, TargetExtractionResult)
        self.assertCountEqual(result.targets, ["host.local", "2.2.2.2", "10.0.0.3"])
        self.assertEqual(len(result.ip_to_asset_id_map), 3)
    
    def test_extract_targets_seen_ip(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "assets", TARGET_PROPERTY_SELECTOR_KEY: "seen_ip"}},
            ASSETS_KEY: [self.asset_seen_ip],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["2.2.2.2"])
        self.assertEqual(result.ip_to_asset_id_map, {"2.2.2.2": "a2"})
    
    def test_extract_targets_local_ip(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "assets", TARGET_PROPERTY_SELECTOR_KEY: "local_ip"}},
            ASSETS_KEY: [self.asset_local_ip],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["10.0.0.3"])
        self.assertEqual(result.ip_to_asset_id_map, {"10.0.0.3": "a3"})
    
    def test_extract_targets_local_ip_no_ips(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "assets", TARGET_PROPERTY_SELECTOR_KEY: "local_ip"}},
            ASSETS_KEY: [self.empty_asset_ips],
        }
        with self.assertRaises(ValueError):
            NucleiContracts.extract_targets(data)
    
    def test_extract_targets_hostname(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "assets", TARGET_PROPERTY_SELECTOR_KEY: "hostname"}},
            ASSETS_KEY: [self.asset_hostname],
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["host.local"])
        self.assertEqual(result.ip_to_asset_id_map, {"host.local": "a1"})
    
    def test_extract_targets_manual(self):
        data = {
            "injection": {"inject_content": {TARGET_SELECTOR_KEY: "manual", TARGETS_KEY: "foo.com, bar.com , ,baz.com"}},
        }
        result = NucleiContracts.extract_targets(data)
        self.assertEqual(result.targets, ["foo.com", "bar.com", "baz.com"])
        self.assertEqual(result.ip_to_asset_id_map, {})
    
    def test_extract_targets_no_targets(self):
        data = {"injection": {"inject_content": {TARGET_SELECTOR_KEY: "unknown"}}}
        with self.assertRaises(ValueError):
            NucleiContracts.extract_targets(data)
