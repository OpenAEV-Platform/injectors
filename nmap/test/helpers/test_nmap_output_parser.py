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
        self.assertTrue(
            result["message"].startswith(
                "2/3 targets scanned, 2 up, 1 missed, 2 open ports"
            )
        )
        self.assertEqual(result["status"], "WARNING")
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
        self.assertEqual(result["status"], "EXECUTED")
        self.assertTrue(result["message"].startswith("3/3 targets scanned, 3 up"))

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

    # ----------------------------------------------------------------
    # Per-target outcomes and the global status
    # ----------------------------------------------------------------

    def test_outcomes_up_down_and_unresolved(self):
        """(a) One host up with open ports, one host down, one hostname not
        resolved: three outcomes EXECUTED / WARNING / WARNING, global WARNING with
        the counts."""
        results = TargetExtractionResult(
            targets=["10.0.0.1", "10.0.0.2", "does-not-exist.invalid"],
            ip_to_asset_id_map={
                "10.0.0.1": "a1",
                "10.0.0.2": "a2",
                "does-not-exist.invalid": "a3",
            },
            resolutions=[
                TargetResolution("10.0.0.1", "a1", "web-01"),
                TargetResolution("10.0.0.2", "a2", "db-02"),
                TargetResolution("does-not-exist.invalid", "a3", "app-03"),
            ],
        )
        down_host = (
            '<host><status state="up" reason="user-set"/>'
            '<address addr="10.0.0.2" addrtype="ipv4"/><hostnames/>'
            '<ports><extraports state="filtered" count="1000"/></ports></host>'
        )
        up_host = (
            '<host><status state="up" reason="user-set"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/><hostnames/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh"/></port>'
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https"/></port></ports></host>'
        )
        result = NmapOutputParser.xmlparse(
            _report(up_host, down_host),
            "asset-groups",
            results,
            stderr=b'Failed to resolve "does-not-exist.invalid".\n',
        )

        self.assertEqual(
            [(o.status, o.describe()) for o in result["outcomes"]],
            [
                ("EXECUTED", "10.0.0.1 (asset web-01): host up, 2 open ports"),
                ("WARNING", "10.0.0.2 (asset db-02): no response, 1000 ports filtered"),
                (
                    "WARNING",
                    "does-not-exist.invalid (asset app-03): not scanned, "
                    "hostname did not resolve",
                ),
            ],
        )
        self.assertEqual(result["status"], "WARNING")
        self.assertTrue(
            result["message"].startswith(
                "2/3 targets scanned, 1 up, 2 missed, 2 open ports"
            )
        )
        # Findings are kept for the host that answered.
        self.assertEqual(sorted(result["outputs"]["ports"]), [22, 443])

    @staticmethod
    def _silent_outcome(
        ports_xml: str, status: str = '<status state="up" reason="user-set"/>'
    ) -> str:
        host = (
            f"<host>{status}"
            '<address addr="10.0.0.2" addrtype="ipv4"/><hostnames/>'
            f"{ports_xml}</host>"
        )
        result = NmapOutputParser.xmlparse(
            _report(host),
            "assets",
            TargetExtractionResult(
                targets=["10.0.0.2"], ip_to_asset_id_map={"10.0.0.2": "a2"}
            ),
        )
        return result["outcomes"][0].describe()

    def test_all_ports_filtered_with_no_reply_is_named(self):
        """-Pn with every probe unanswered: no reply, told apart from a reject."""
        self.assertEqual(
            self._silent_outcome(
                '<ports><extraports state="filtered" count="1000">'
                '<extrareasons reason="no-response" count="1000"/>'
                "</extraports></ports>"
            ),
            "10.0.0.2 (asset a2): no response, 1000 ports filtered, no reply "
            "(host down or every probe dropped)",
        )

    def test_ports_rejected_by_icmp_say_a_firewall_answered(self):
        self.assertEqual(
            self._silent_outcome(
                '<ports><extraports state="filtered" count="999">'
                '<extrareasons reason="admin-prohibited" count="999"/>'
                "</extraports>"
                '<port protocol="tcp" portid="22"><state state="filtered" '
                'reason="no-response"/></port></ports>'
            ),
            "10.0.0.2 (asset a2): no response, 1000 ports filtered, 999 rejected "
            "by ICMP admin-prohibited (a firewall answered)",
        )

    def test_host_discovery_down_is_named(self):
        self.assertEqual(
            self._silent_outcome(
                "", status='<status state="down" reason="no-response"/>'
            ),
            "10.0.0.2 (asset a2): no response, host down (no reply to host "
            "discovery)",
        )

    def test_silent_host_without_ports_keeps_the_generic_wording(self):
        self.assertEqual(
            self._silent_outcome("", status='<status state="up" reason="user-set"/>'),
            "10.0.0.2 (asset a2): host down or no response",
        )

    def test_outcomes_all_hosts_up(self):
        """(b) Every target answered: global EXECUTED."""
        results = TargetExtractionResult(
            targets=["10.0.0.1", "10.0.0.2"],
            ip_to_asset_id_map={"10.0.0.1": "a1", "10.0.0.2": "a2"},
        )
        result = NmapOutputParser.xmlparse(
            _report(_host("10.0.0.1", 22), _host("10.0.0.2", 80)), "assets", results
        )
        self.assertEqual(result["status"], "EXECUTED")
        self.assertEqual([o.status for o in result["outcomes"]], ["EXECUTED"] * 2)
        self.assertEqual(
            result["message"], "2/2 targets scanned, 2 up, 0 missed, 2 open ports"
        )

    def test_host_up_with_only_closed_ports(self):
        host = (
            '<host><status state="up" reason="user-set"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/><hostnames/>'
            '<ports><extraports state="closed" count="1000"/></ports></host>'
        )
        result = NmapOutputParser.xmlparse(
            _report(host),
            "assets",
            TargetExtractionResult(
                targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
            ),
        )
        self.assertEqual(
            result["outcomes"][0].describe(),
            "10.0.0.1 (asset a1): host up, no open port",
        )
        self.assertEqual(result["status"], "EXECUTED")

    def test_nonzero_exit_code_with_report_is_warning(self):
        """(c) parser side: the exit code turns the status to WARNING and is named."""
        result = NmapOutputParser.xmlparse(
            _report(_host("10.0.0.1", 22)),
            "assets",
            TargetExtractionResult(
                targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
            ),
            exit_code=1,
        )
        self.assertEqual(result["status"], "WARNING")
        self.assertIn("nmap exited with code 1, results kept", result["message"])
        self.assertEqual(result["outputs"]["ports"], [22])

    def test_nonzero_exit_code_with_no_host_is_error_with_stderr(self):
        """An nmaprun header with no host on a non-zero exit: nothing was scanned,
        the status is ERROR and nmap's stderr closes the message."""
        result = NmapOutputParser.xmlparse(
            b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>',
            "assets",
            TargetExtractionResult(
                targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
            ),
            stderr=b"NSE: failed to initialize the script engine\n",
            exit_code=1,
        )
        self.assertEqual(result["status"], "ERROR")
        self.assertTrue(
            result["message"].endswith(
                "nmap stderr:\nNSE: failed to initialize the script engine"
            )
        )

    def test_zero_exit_code_with_no_host_is_unchanged(self):
        """Exit 0 with no host keeps the former WARNING and no stderr line."""
        result = NmapOutputParser.xmlparse(
            b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>',
            "assets",
            TargetExtractionResult(
                targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
            ),
            stderr=b"Starting Nmap\n",
        )
        self.assertEqual(result["status"], "WARNING")
        self.assertNotIn("stderr", result["message"])

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
