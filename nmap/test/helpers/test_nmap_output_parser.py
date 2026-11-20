from unittest import TestCase

from injector_common.targets import TargetExtractionResult
from nmap.helpers.nmap_output_parser import NmapOutputParser


class NmapOutputParserTest(TestCase):
    def setUp(self):
        self.result_single_host = b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -Pn -sT -oX - scanme.nmap.org" start="1780584711" startstr="Thu Jun  4 16:51:51 2026" version="7.99" xmloutputversion="1.05"><host starttime="1780584711" endtime="1780584715"><status state="up" reason="user-set" reason_ttl="0"/><address addr="45.33.32.156" addrtype="ipv4"/><hostnames><hostname name="scanme.nmap.org" type="user"/><hostname name="scanme.nmap.org" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port><port protocol="tcp" portid="25"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="smtp" method="table" conf="3"/></port><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" method="table" conf="3"/></port><port protocol="tcp" portid="9929"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></port><port protocol="tcp" portid="31337"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="Elite" method="table" conf="3"/></port></ports></host><runstats><finished time="1780584715" timestr="Thu Jun  4 16:51:55 2026" summary="Nmap done at Thu Jun  4 16:51:55 2026; 1 IP address (1 host up) scanned in 3.95 seconds" elapsed="3.95" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'
        self.result_no_open_ports = b'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="nmap -Pn -sT -oX - 10.0.0.9" start="1780584711" startstr="Thu Jun  4 16:51:51 2026" version="7.99" xmloutputversion="1.05"><host starttime="1780584711" endtime="1780584715"><status state="up" reason="user-set" reason_ttl="0"/><address addr="10.0.0.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port></ports></host><runstats><finished time="1780584715" timestr="Thu Jun  4 16:51:55 2026" summary="Nmap done" elapsed="3.95" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'

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
        self.assertEqual(scan["service"], "ssh, guessed from port")
        self.assertEqual(scan["service_confidence"], "guessed")

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
        self.assertEqual(scan["service"], "ssh, guessed from port")

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

    # ----------------------------------------------------------------
    # service labels: guessed from nmap's port table vs probed by -sV
    # ----------------------------------------------------------------

    @staticmethod
    def _single_port_report(service_element: str) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?><nmaprun scanner="nmap">'
            '<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="9100">'
            '<state state="open" reason="syn-ack"/>'
            f"{service_element}</port></ports></host></nmaprun>"
        ).encode()

    def _scan_of(self, service_element: str) -> dict:
        result = NmapOutputParser.xmlparse(
            self._single_port_report(service_element),
            "manual",
            TargetExtractionResult(ip_to_asset_id_map={}, targets=["10.0.0.5"]),
        )
        return result["outputs"]["scan_results"][0]

    def test_service_from_port_table_is_marked_guessed(self):
        """Without -sV nmap names 9100/tcp 'jetdirect' from its port table: the
        finding must say the label is a guess, not a detected printer."""
        scan = self._scan_of('<service name="jetdirect" method="table" conf="3"/>')

        self.assertEqual(scan["port"], 9100)
        self.assertEqual(scan["service"], "jetdirect, guessed from port")
        self.assertEqual(scan["service_confidence"], "guessed")
        self.assertNotIn("service_product", scan)

    def test_probed_service_carries_product_and_version(self):
        scan = self._scan_of(
            '<service name="http" product="Prometheus node_exporter" version="1.x" '
            'method="probed" conf="10"/>'
        )

        self.assertEqual(scan["service"], "http, Prometheus node_exporter 1.x")
        self.assertEqual(scan["service_confidence"], "probed")
        self.assertEqual(scan["service_product"], "Prometheus node_exporter")
        self.assertEqual(scan["service_version"], "1.x")

    def test_probed_service_with_extrainfo(self):
        scan = self._scan_of(
            '<service name="ssh" product="OpenSSH" version="9.6p1" '
            'extrainfo="protocol 2.0" method="probed" conf="10"/>'
        )

        self.assertEqual(scan["service"], "ssh, OpenSSH 9.6p1, protocol 2.0")
        self.assertEqual(scan["service_extrainfo"], "protocol 2.0")

    def test_probed_service_without_product_keeps_its_name(self):
        scan = self._scan_of('<service name="http" method="probed" conf="10"/>')

        self.assertEqual(scan["service"], "http")
        self.assertEqual(scan["service_confidence"], "probed")

    def test_port_without_service_element(self):
        scan = self._scan_of("")

        self.assertEqual(scan["service"], "missing name")
        self.assertEqual(scan["service_confidence"], "guessed")

    def test_scan_results_keep_the_chaining_keys(self):
        scan = self._scan_of('<service name="jetdirect" method="table" conf="3"/>')

        for key in ("asset_id", "host", "port", "service"):
            self.assertIn(key, scan)

    # ----------------------------------------------------------------
    # action_output: raw XML report, always routed on a successful parse,
    # independent of the structured PortsScan/Port extraction above.
    # ----------------------------------------------------------------

    def test_action_output_present_for_valid_scan(self):
        result = NmapOutputParser.xmlparse(
            self.result_single_host,
            "manual",
            TargetExtractionResult(ip_to_asset_id_map={}, targets=["45.33.32.156"]),
        )
        self.assertIn("action_output", result["outputs"])
        self.assertIn("scanme.nmap.org", result["outputs"]["action_output"])

    def test_action_output_present_with_zero_open_ports(self):
        """A scan that finds nothing structured still routes the raw XML."""
        result = NmapOutputParser.xmlparse(
            self.result_no_open_ports,
            "manual",
            TargetExtractionResult(ip_to_asset_id_map={}, targets=["10.0.0.9"]),
        )
        self.assertEqual(result["outputs"]["scan_results"], [])
        self.assertEqual(result["outputs"]["ports"], [])
        self.assertIn("action_output", result["outputs"])
        self.assertIn("10.0.0.9", result["outputs"]["action_output"])

    def test_wrong_root_tag_raises(self):
        """Well-formed XML, but not an nmap report: still fails fast, no
        outputs dict is built."""
        with self.assertRaises(ValueError):
            NmapOutputParser.xmlparse(
                b"<?xml version='1.0'?><notnmaprun></notnmaprun>",
                "manual",
                TargetExtractionResult(ip_to_asset_id_map={}, targets=[]),
            )

    def test_truncated_xml_raises(self):
        """Genuinely malformed/truncated XML: lxml itself rejects it before
        the root-tag check ever runs."""
        from lxml.etree import XMLSyntaxError

        with self.assertRaises(XMLSyntaxError):
            NmapOutputParser.xmlparse(
                b'<?xml version="1.0"?><nmaprun><host><address addr="1.2.3.4"',
                "manual",
                TargetExtractionResult(ip_to_asset_id_map={}, targets=[]),
            )
