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

    def test_shodaninjector_normalize_input_data_case_asset_groups(self, m_api):
        config = MagicMock()
        helper = MagicMock()

        injector = module.ShodanInjector(config=config, helper=helper)

        inject_content = {
            "expectations": [],
            "target_selector": "asset-groups",
            "target_property_selector": "automatic",
            "auto_create_assets": False,
            "hostname": "",
            "organization": "",
        }
        # The asset group holds more assets than the ones in the message: the
        # platform only sends the assets the user launching the inject has clearance on.
        asset_zero = {
            "asset_id": "asset-zero-id",
            "asset_hostname": "asset.hostname.local",
            "asset_ips": ["1.2.3.4"],
            "asset_seen_ip": "1.2.3.4",
            "asset_groups": [{"asset_group_id": "group-id"}],
        }
        asset_one = {
            "asset_id": "asset-one-id",
            "asset_hostname": "endpoint.hostname.local",
            "asset_ips": ["5.6.7.8"],
            "asset_seen_ip": "5.6.7.8",
            "asset_groups": [{"asset_group_id": "group-id"}],
        }
        data = {
            "injection": {
                "inject_injector_contract": {
                    "convertedContent": {
                        "contract_id": module.ShodanContractId.CVE_ENUMERATION.value
                    }
                },
                "inject_content": inject_content,
            },
            "assetGroups": [
                {"asset_group_id": "group-id", "asset_group_name": "Group"}
            ],
            "assets": [asset_zero, asset_one],
        }

        normalize_input_data = injector._normalize_input_data(
            data, inject_content, "asset-groups", "automatic"
        )

        targets = normalize_input_data.targets
        self.assertEqual(targets.selector_key, "asset-groups")
        self.assertEqual(targets.asset_ids, ["asset-zero-id", "asset-one-id"])
        self.assertEqual(
            targets.hostnames, ["asset.hostname.local", "endpoint.hostname.local"]
        )
        self.assertEqual(targets.ips, ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(targets.seen_ips, ["1.2.3.4", "5.6.7.8"])
        # The assets of the groups are never fetched from the API, which would
        # bypass the clearance filtering done by the platform.
        helper.api.endpoint.searchTargets.assert_not_called()

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
