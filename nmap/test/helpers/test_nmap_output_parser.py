from unittest import TestCase

from src.helpers.nmap_output_parser import NmapOutputParser

parse = NmapOutputParser()


class NmapOutputParserTest(TestCase):
    def setUp(self):
        self.data_assets = {
            "injection": {"inject_content": {"target_selector": "assets"}}
        }

        self.data_no_assets = {
            "injection": {"inject_content": {"target_selector": "other"}}
        }

        self.result_multiple_hosts = {
            "nmaprun": {
                "host": [
                    {
                        "address": {"@addr": "10.0.0.1"},
                        "ports": {
                            "port": [
                                {
                                    "@portid": "22",
                                    "state": {"@state": "open"},
                                    "service": {"@name": "ssh"},
                                },
                                {
                                    "@portid": "80",
                                    "state": {"@state": "closed"},
                                    "service": {"@name": "http"},
                                },
                            ]
                        },
                    },
                    {
                        "address": {"@addr": "10.0.0.2"},
                        "ports": {
                            "port": [
                                {
                                    "@portid": "443",
                                    "state": {"@state": "open"},
                                    "service": {"@name": "https"},
                                }
                            ]
                        },
                    },
                ]
            }
        }

        self.result_single_host = {
            "nmaprun": {
                "host": {
                    "address": {"@addr": "172.16.5.10"},
                    "ports": {
                        "port": [
                            {
                                "@portid": "21",
                                "state": {"@state": "open"},
                                "service": {"@name": "ftp"},
                            }
                        ]
                    },
                }
            }
        }

    # -------------------------------
    # Tests
    # -------------------------------

    def test_parse_target_assets(self):
        """Ensure target_selector='assets' uses asset_list and sets asset_id."""
        data = {"injection": {"inject_content": {"target_selector": "assets"}}}

        result = parse(data, self.result_single_host, ["asset-123"])

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "asset-123")
        self.assertEqual(scan["host"], "172.16.5.10")
        self.assertEqual(scan["port"], 21)
        self.assertEqual(scan["service"], "ftp")

    def test_parse_target_asset_groups(self):
        """Ensure target_selector='asset-groups' also uses asset_list."""
        data = {"injection": {"inject_content": {"target_selector": "asset-groups"}}}

        result = parse(data, self.result_single_host, ["group-asset-555"])

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "group-asset-555")
        self.assertEqual(scan["host"], "172.16.5.10")
        self.assertEqual(scan["port"], 21)
        self.assertEqual(scan["service"], "ftp")

    def test_parse_target_manual(self):
        """Ensure target_selector='manual' sets asset_id=None."""
        data = {"injection": {"inject_content": {"target_selector": "manual"}}}

        result = parse(data, self.result_single_host, ["ignored"])

        scan = result["outputs"]["scan_results"][0]

        self.assertIsNone(scan["asset_id"])
        self.assertEqual(scan["host"], "172.16.5.10")
        self.assertEqual(scan["port"], 21)
        self.assertEqual(scan["service"], "ftp")
