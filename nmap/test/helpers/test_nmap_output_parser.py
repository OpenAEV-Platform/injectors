from unittest import TestCase

from injector_common.targets import TargetExtractionResult, TargetResolution
from nmap.helpers.nmap_output_parser import NmapOutputParser


def _host(addr: str, port: int, hostname: str = "") -> str:
    names = (
        f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
        if hostname
        else "<hostnames/>"
    )
    return (
        f'<host><status state="up"/><address addr="{addr}" addrtype="ipv4"/>{names}'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="svc{port}"/></port></ports></host>'
    )


def _report(*hosts: str) -> bytes:
    return (
        '<?xml version="1.0"?><nmaprun scanner="nmap">' + "".join(hosts) + "</nmaprun>"
    ).encode()


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

    # ----------------------------------------------------------------
    # Attribution by address/hostname, never by position
    # ----------------------------------------------------------------

    def test_unresolved_first_target_does_not_shift_attribution(self):
        """Three targets, the first an unresolvable hostname: nmap emits two hosts.
        Each host's ports go to its own asset and the first target is reported."""
        results = TargetExtractionResult(
            targets=["does-not-exist.invalid", "10.0.0.2", "10.0.0.3"],
            ip_to_asset_id_map={
                "does-not-exist.invalid": "a1",
                "10.0.0.2": "a2",
                "10.0.0.3": "a3",
            },
            resolutions=[
                TargetResolution(
                    "does-not-exist.invalid", "a1", "web-01", "hostname", "automatic"
                ),
                TargetResolution("10.0.0.2", "a2", None, "seen_ip", "automatic"),
                TargetResolution("10.0.0.3", "a3", None, "seen_ip", "automatic"),
            ],
        )
        stderr = b'Failed to resolve "does-not-exist.invalid".\n'
        result = NmapOutputParser.xmlparse(
            _report(_host("10.0.0.2", 22), _host("10.0.0.3", 80)),
            "asset-groups",
            results,
            stderr=stderr,
        )

        by_port = {s["port"]: s for s in result["outputs"]["scan_results"]}
        self.assertEqual(by_port[22]["asset_id"], "a2")
        self.assertEqual(by_port[80]["asset_id"], "a3")
        self.assertEqual(len(result["missed"]), 1)
        self.assertEqual(
            result["missed"][0].describe(),
            "does-not-exist.invalid (asset web-01): not scanned, "
            "hostname did not resolve",
        )
        self.assertIn("1 target(s) not scanned", result["message"])
        self.assertIn("does-not-exist.invalid (asset web-01)", result["message"])

    def test_hostname_target_matched_by_xml_hostname(self):
        """A target given as a hostname is matched by the host's hostname entry."""
        results = TargetExtractionResult(
            targets=["10.0.0.9", "scanme.nmap.org"],
            ip_to_asset_id_map={"10.0.0.9": "a9", "scanme.nmap.org": "a1"},
        )
        result = NmapOutputParser.xmlparse(self.result_single_host, "assets", results)

        asset_ids = {s["asset_id"] for s in result["outputs"]["scan_results"]}
        self.assertEqual(asset_ids, {"a1"})
        # 10.0.0.9 produced no host: an IP target missed is reported, not attributed.
        self.assertEqual([m.resolution.target for m in result["missed"]], ["10.0.0.9"])
        self.assertEqual(result["missed"][0].reason, "no result returned by the scan")

    def test_duplicate_target_values_do_not_shift_attribution(self):
        """Two assets resolving to one value collapse in the map; the hosts after
        them must still be attributed to their own asset."""
        results = TargetExtractionResult(
            targets=["10.0.0.1", "10.0.0.1", "10.0.0.2"],
            ip_to_asset_id_map={"10.0.0.1": "a1b", "10.0.0.2": "a2"},
            resolutions=[
                TargetResolution("10.0.0.1", "a1"),
                TargetResolution("10.0.0.1", "a1b"),
                TargetResolution("10.0.0.2", "a2"),
            ],
        )
        result = NmapOutputParser.xmlparse(
            _report(_host("10.0.0.1", 22), _host("10.0.0.2", 443)),
            "assets",
            results,
        )

        port_443 = [s for s in result["outputs"]["scan_results"] if s["port"] == 443]
        self.assertEqual([s["asset_id"] for s in port_443], ["a2"])
        port_22 = sorted(
            s["asset_id"] for s in result["outputs"]["scan_results"] if s["port"] == 22
        )
        self.assertEqual(port_22, ["a1", "a1b"])
        self.assertEqual(result["missed"], [])
        self.assertTrue(result["message"].startswith("Targets successfully scanned"))

    def test_host_matching_no_target_keeps_asset_id_none(self):
        results = TargetExtractionResult(
            targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
        )
        result = NmapOutputParser.xmlparse(
            _report(_host("10.0.0.1", 22), _host("10.9.9.9", 80)), "assets", results
        )
        by_port = {s["port"]: s for s in result["outputs"]["scan_results"]}
        self.assertEqual(by_port[22]["asset_id"], "a1")
        self.assertIsNone(by_port[80]["asset_id"])

    def test_unresolved_targets_read_from_stderr(self):
        self.assertEqual(
            NmapOutputParser.unresolved_targets(
                b'Failed to resolve "a.invalid".\nFailed to resolve "b.invalid".\n'
            ),
            ["a.invalid", "b.invalid"],
        )
        self.assertEqual(NmapOutputParser.unresolved_targets(None), [])

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
