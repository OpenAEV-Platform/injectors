import unittest
from unittest.mock import MagicMock, patch

import shodan.injector.openaev_shodan as module
from shodan.contracts import InjectorKey


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

    # ----------------------------------------------------------------
    # Findings collection (_prepare_output_structured)
    # ----------------------------------------------------------------

    @staticmethod
    def _results(*matches):
        return {"data": [{"url": None, "result": {"matches": list(matches)}}]}

    def test_prepare_output_structured_validates_findings(self, m_api):
        injector = module.ShodanInjector(config=MagicMock(), helper=MagicMock())

        shodan_results = self._results(
            {
                "ip_str": "51.38.220.153",
                "hostnames": ["automation.filigran.io"],
                "port": 443,
                "vulns": {"CVE-2023-44487": {}, "cve-2025-23419": {}},
            },
            # No hostname: a banner still yields host / port / CVE findings.
            {
                "ip_str": "142.250.80.46",
                "hostnames": [],
                "port": "80",
                "vulns": {"CVE-2019-8936": {}, "NOT-A-CVE": {}},
            },
            # IPv6 and malformed IPs are dropped from the IPv4 `hosts` output.
            {"ip_str": "2001:db8::1", "hostnames": [], "port": 22},
            {"ip_str": "not-an-ip", "hostnames": [], "port": 70000},
            # Booleans and out-of-range ports never reach the Port output.
            {"ip_str": "8.8.8.8", "hostnames": [], "port": True},
        )

        structured = injector._prepare_output_structured(shodan_results)

        self.assertEqual(
            structured["hosts"], ["142.250.80.46", "51.38.220.153", "8.8.8.8"]
        )
        self.assertEqual(structured["ports"], [22, 80, 443])
        self.assertEqual(
            structured["cves"],
            ["CVE-2019-8936", "CVE-2023-44487", "CVE-2025-23419"],
        )

    def test_prepare_output_structured_deduplicates_findings(self, m_api):
        injector = module.ShodanInjector(config=MagicMock(), helper=MagicMock())

        shodan_results = self._results(
            {
                "ip_str": "1.1.1.1",
                "hostnames": [],
                "port": 443,
                "vulns": {"CVE-2023-1111": {}},
            },
            {
                "ip_str": "1.1.1.1",
                "hostnames": [],
                "port": 443,
                "vulns": {"CVE-2023-1111": {}},
            },
        )

        structured = injector._prepare_output_structured(shodan_results)

        self.assertEqual(structured["hosts"], ["1.1.1.1"])
        self.assertEqual(structured["ports"], [443])
        self.assertEqual(structured["cves"], ["CVE-2023-1111"])
        self.assertEqual(structured["found_assets"], [])

    # ----------------------------------------------------------------
    # Findings are always emitted; assets stay opt-in (_shodan_execution)
    # ----------------------------------------------------------------

    def _run_execution(self, injector, *, auto_create_assets):
        structured = {
            "found_assets": [{"name": "host.local"}],
            "hosts": ["1.2.3.4"],
            "ports": [443],
            "cves": ["CVE-2023-1111"],
        }
        data = {
            "injection": {
                "inject_content": {
                    InjectorKey.TARGET_SELECTOR_KEY: "manual",
                    InjectorKey.TARGET_PROPERTY_SELECTOR_KEY: "automatic",
                }
            }
        }
        normalize_input_data = MagicMock()
        normalize_input_data.inject_content.auto_create_assets = auto_create_assets
        injector.shodan_client_api.process_shodan_search.return_value = ({}, {})
        with patch.object(
            injector, "_normalize_input_data", return_value=normalize_input_data
        ), patch.object(
            injector, "_prepare_output_structured", return_value=structured
        ), patch.object(
            injector, "_prepare_output_message", return_value="message"
        ):
            return injector._shodan_execution(data)

    def test_shodan_execution_emits_findings_without_assets(self, m_api):
        injector = module.ShodanInjector(config=MagicMock(), helper=MagicMock())

        output_structured, _ = self._run_execution(injector, auto_create_assets=False)

        self.assertEqual(output_structured["hosts"], ["1.2.3.4"])
        self.assertEqual(output_structured["ports"], [443])
        self.assertEqual(output_structured["cves"], ["CVE-2023-1111"])
        self.assertNotIn("found_assets", output_structured)

    def test_shodan_execution_includes_assets_when_opted_in(self, m_api):
        injector = module.ShodanInjector(config=MagicMock(), helper=MagicMock())

        output_structured, _ = self._run_execution(injector, auto_create_assets=True)

        self.assertEqual(output_structured["found_assets"], [{"name": "host.local"}])
        self.assertEqual(output_structured["hosts"], ["1.2.3.4"])
