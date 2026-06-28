from unittest import TestCase

from injector_common.targets import TargetExtractionResult
from nmap.helpers.nmap_output_parser import NmapOutputParser


class NmapOutputParserTest(TestCase):
    def setUp(self):
        self.result_single_host = b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -Pn -sT -oX - scanme.nmap.org" start="1780584711" startstr="Thu Jun  4 16:51:51 2026" version="7.99" xmloutputversion="1.05"><host starttime="1780584711" endtime="1780584715"><status state="up" reason="user-set" reason_ttl="0"/><address addr="45.33.32.156" addrtype="ipv4"/><hostnames><hostname name="scanme.nmap.org" type="user"/><hostname name="scanme.nmap.org" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port><port protocol="tcp" portid="25"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="smtp" method="table" conf="3"/></port><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" method="table" conf="3"/></port><port protocol="tcp" portid="9929"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></port><port protocol="tcp" portid="31337"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="Elite" method="table" conf="3"/></port></ports></host><runstats><finished time="1780584715" timestr="Thu Jun  4 16:51:55 2026" summary="Nmap done at Thu Jun  4 16:51:55 2026; 1 IP address (1 host up) scanned in 3.95 seconds" elapsed="3.95" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'

    # -------------------------------
    # Tests
    # -------------------------------

    def test_parse_target_assets(self):
        """Ensure target_selector='assets' uses asset_list and sets asset_id."""
        result = NmapOutputParser.xmlparse(
            self.result_single_host,
            "assets",
            TargetExtractionResult(
                ip_to_asset_id_map={"45.33.32.156": "asset-123"}, targets=[]
            ),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "asset-123")
        self.assertEqual(scan["host"], "45.33.32.156")
        self.assertEqual(scan["port"], 22)
        self.assertEqual(scan["service"], "ssh")

    def test_parse_target_asset_groups(self):
        """Ensure target_selector='asset-groups' also uses asset_list."""
        result = NmapOutputParser.xmlparse(
            self.result_single_host,
            "asset-groups",
            TargetExtractionResult(
                ip_to_asset_id_map={"45.33.32.156": "group-asset-555"},
                targets=["45.33.32.156"],
            ),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertEqual(scan["asset_id"], "group-asset-555")
        self.assertEqual(scan["host"], "45.33.32.156")
        self.assertEqual(scan["port"], 22)
        self.assertEqual(scan["service"], "ssh")

    def test_parse_target_manual(self):
        """Ensure target_selector='manual' sets asset_id=None."""
        result = NmapOutputParser.xmlparse(
            self.result_single_host,
            "manual",
            TargetExtractionResult(ip_to_asset_id_map={}, targets=["45.33.32.156"]),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertIsNone(scan["asset_id"])
        self.assertEqual(scan["host"], "45.33.32.156")

    def test_parse_target_manual_None_values(self):
        """Ensure target_selector='manual' sets asset_id=None."""
        result = NmapOutputParser.xmlparse(
            self.result_single_host,
            "manual",
            TargetExtractionResult(ip_to_asset_id_map={}, targets=[]),
        )

        scan = result["outputs"]["scan_results"][0]

        self.assertIsNone(scan["asset_id"])
        self.assertIsNone(scan["host"])
