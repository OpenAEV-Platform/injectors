import unittest
from unittest.mock import MagicMock, patch

import shodan.injector.openaev_shodan as module


@patch.object(module, "ShodanClientAPI")
class TestShodanInjector(unittest.TestCase):
    def test_shodaninjector_init(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        self.assertEqual(injector.config, config)
        self.assertEqual(injector.helper, helper)
        self.assertEqual(injector.shodan_client_api, m_api.return_value)

        m_api.assert_called_once_with(config, helper)

    def test_shodaninjector_build_targets_from_assets_case_automatic(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        selector_property = "automatic"
        targets = {
            "assets": [],
            "asset_ids": [],
            "ips": [],
            "hostnames": [],
            "seen_ips": [],
        }
        asset_zero = {
            "asset_id": "asset-zero-id",
            "asset_hostname": "asset.hostname.local",
            "asset_ips": ["1.2.3.4"],
            "asset_seen_ip": "1.2.3.4",
        }
        asset_one = {
            "asset_id": "asset-one-id",
            "asset_hostname": "endpoint.hostname.local",
            "asset_ips": ["5.6.7.8"],
            "asset_seen_ip": "5.6.7.8",
        }
        assets = [asset_zero, asset_one]

        injector._build_targets_from_assets(selector_property, targets, assets)

        self.assertEqual(targets["asset_ids"], ["asset-zero-id", "asset-one-id"])
        self.assertEqual(
            targets["hostnames"], ["asset.hostname.local", "endpoint.hostname.local"]
        )
        self.assertEqual(targets["ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(targets["seen_ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(
            targets["assets"],
            [
                {
                    "asset_id": "asset-zero-id",
                    "asset_hostname": "asset.hostname.local",
                    "asset_ips": ["1.2.3.4"],
                    "asset_seen_ip": "1.2.3.4",
                },
                {
                    "asset_id": "asset-one-id",
                    "asset_hostname": "endpoint.hostname.local",
                    "asset_ips": ["5.6.7.8"],
                    "asset_seen_ip": "5.6.7.8",
                },
            ],
        )

    def test_shodaninjector_build_targets_from_assets_case_hostname(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        selector_property = "hostname"
        targets = {
            "assets": [],
            "asset_ids": [],
            "ips": [],
            "hostnames": [],
            "seen_ips": [],
        }
        asset_zero = {
            "asset_id": "asset-zero-id",
            "asset_hostname": "asset.hostname.local",
        }
        asset_one = {
            "asset_id": "asset-one-id",
            "asset_hostname": "endpoint.hostname.local",
        }
        assets = [asset_zero, asset_one]

        injector._build_targets_from_assets(selector_property, targets, assets)

        self.assertEqual(targets["asset_ids"], ["asset-zero-id", "asset-one-id"])
        self.assertEqual(
            targets["hostnames"], ["asset.hostname.local", "endpoint.hostname.local"]
        )
        self.assertEqual(
            targets["assets"],
            [
                {
                    "asset_id": "asset-zero-id",
                    "asset_hostname": "asset.hostname.local",
                    "asset_ips": [],
                    "asset_seen_ip": None,
                },
                {
                    "asset_id": "asset-one-id",
                    "asset_hostname": "endpoint.hostname.local",
                    "asset_ips": [],
                    "asset_seen_ip": None,
                },
            ],
        )

    def test_shodaninjector_build_targets_from_assets_case_local_ip(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        selector_property = "local_ip"
        targets = {
            "assets": [],
            "asset_ids": [],
            "ips": [],
            "hostnames": [],
            "seen_ips": [],
        }
        asset_zero = {
            "asset_id": "asset-zero-id",
            "asset_ips": ["1.2.3.4"],
        }
        asset_one = {
            "asset_id": "asset-one-id",
            "asset_ips": ["5.6.7.8"],
        }
        assets = [asset_zero, asset_one]

        injector._build_targets_from_assets(selector_property, targets, assets)

        self.assertEqual(targets["asset_ids"], ["asset-zero-id", "asset-one-id"])
        self.assertEqual(targets["ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(
            targets["assets"],
            [
                {
                    "asset_id": "asset-zero-id",
                    "asset_hostname": None,
                    "asset_ips": ["1.2.3.4"],
                    "asset_seen_ip": None,
                },
                {
                    "asset_id": "asset-one-id",
                    "asset_hostname": None,
                    "asset_ips": ["5.6.7.8"],
                    "asset_seen_ip": None,
                },
            ],
        )

    def test_shodaninjector_build_targets_from_assets_case_seen_ip(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        selector_property = "seen_ip"
        targets = {
            "assets": [],
            "asset_ids": [],
            "ips": [],
            "hostnames": [],
            "seen_ips": [],
        }
        asset_zero = {
            "asset_id": "asset-zero-id",
            "asset_seen_ip": "1.2.3.4",
        }
        asset_one = {
            "asset_id": "asset-one-id",
            "asset_seen_ip": "5.6.7.8",
        }
        assets = [asset_zero, asset_one]

        injector._build_targets_from_assets(selector_property, targets, assets)

        self.assertEqual(targets["asset_ids"], ["asset-zero-id", "asset-one-id"])
        self.assertEqual(targets["seen_ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(
            targets["assets"],
            [
                {
                    "asset_id": "asset-zero-id",
                    "asset_hostname": None,
                    "asset_ips": [],
                    "asset_seen_ip": "1.2.3.4",
                },
                {
                    "asset_id": "asset-one-id",
                    "asset_hostname": None,
                    "asset_ips": [],
                    "asset_seen_ip": "5.6.7.8",
                },
            ],
        )
