from unittest import TestCase

from injector_common.targets import TargetExtractionResult

from src.helpers.nmap_output_parser import NmapOutputParser


class NmapOutputParserTest(TestCase):
    def setUp(self):
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

        result = NmapOutputParser.parse(
            data,
            self.result_single_host,
            TargetExtractionResult(
                ip_to_asset_id_map={"172.16.5.10": "asset-123"}, targets=[]
            ),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "asset-123")
        self.assertEqual(scan["host"], "172.16.5.10")
        self.assertEqual(scan["port"], 21)
        self.assertEqual(scan["service"], "ftp")

    def test_parse_target_asset_groups(self):
        """Ensure target_selector='asset-groups' also uses asset_list."""
        data = {"injection": {"inject_content": {"target_selector": "asset-groups"}}}

        result = NmapOutputParser.parse(
            data,
            self.result_single_host,
            TargetExtractionResult(
                ip_to_asset_id_map={"172.16.5.10": "group-asset-555"},
                targets=["172.16.5.10"],
            ),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "group-asset-555")
        self.assertEqual(scan["host"], "172.16.5.10")
        self.assertEqual(scan["port"], 21)
        self.assertEqual(scan["service"], "ftp")

    def test_parse_target_manual(self):
        """Ensure target_selector='manual' sets asset_id=None."""
        data = {"injection": {"inject_content": {"target_selector": "manual"}}}

        result = NmapOutputParser.parse(
            data,
            self.result_single_host,
            TargetExtractionResult(ip_to_asset_id_map={}, targets=["172.16.5.10"]),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertIsNone(scan["asset_id"])
        self.assertEqual(scan["host"], "172.16.5.10")

    def test_parse_target_manual_None_values(self):
        """Ensure target_selector='manual' sets asset_id=None."""
        data = {"injection": {"inject_content": {"target_selector": "manual"}}}

        result = NmapOutputParser.parse(
            data,
            self.result_single_host,
            TargetExtractionResult(ip_to_asset_id_map={}, targets=[]),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertIsNone(scan["asset_id"])
        self.assertIsNone(scan["host"])
