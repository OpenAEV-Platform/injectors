import json
import unittest

from dns_enum.helpers.dns_enum_output_parser import DnsEnumOutputParser


def _lines(*entries) -> str:
    return "\n".join(json.dumps(entry) for entry in entries)


class TestDnsEnumOutputParser(unittest.TestCase):
    def test_one_entry_per_resolved_host_sorted(self):
        stdout = _lines(
            {"host": "www.example.com", "a": ["93.184.216.34"]},
            {"host": "api.example.com", "a": ["10.0.0.1", "10.0.0.2"]},
        )
        hosts = DnsEnumOutputParser.parse_hosts(stdout, ["example.com"])
        self.assertEqual(
            [h["host"] for h in hosts], ["api.example.com", "www.example.com"]
        )
        self.assertEqual(hosts[0]["ips"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(hosts[0]["records"], {"A": ["10.0.0.1", "10.0.0.2"]})

    def test_duplicate_lines_are_merged_without_duplicate_values(self):
        stdout = _lines(
            {"host": "WWW.Example.com.", "a": ["1.1.1.1"]},
            {"host": "www.example.com", "a": ["1.1.1.1", "2.2.2.2"], "aaaa": ["::1"]},
        )
        hosts = DnsEnumOutputParser.parse_hosts(stdout, ["example.com"])
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ips"], ["1.1.1.1", "2.2.2.2", "::1"])

    def test_host_without_answer_out_of_scope_or_garbage_is_dropped(self):
        stdout = "\n".join(
            [
                json.dumps({"host": "dead.example.com"}),
                json.dumps({"host": "other.org", "a": ["3.3.3.3"]}),
                json.dumps({"host": "notexample.com", "a": ["4.4.4.4"]}),
                "not json",
                json.dumps(["list"]),
                "",
            ]
        )
        self.assertEqual(DnsEnumOutputParser.parse_hosts(stdout, ["example.com"]), [])

    def test_cname_and_txt_records_are_kept_and_cname_host_has_no_ip(self):
        stdout = _lines(
            {
                "host": "shop.example.com",
                "cname": ["shops.provider.net."],
                "txt": ["v=spf1 -all"],
            }
        )
        hosts = DnsEnumOutputParser.parse_hosts(stdout, ["example.com"])
        self.assertEqual(hosts[0]["ips"], [])
        self.assertEqual(hosts[0]["records"]["CNAME"], ["shops.provider.net"])
        self.assertEqual(hosts[0]["records"]["TXT"], ["v=spf1 -all"])
        self.assertEqual(
            DnsEnumOutputParser.describe(hosts[0]),
            "shop.example.com | CNAME: shops.provider.net | TXT: v=spf1 -all",
        )

    def test_build_outputs(self):
        stdout = _lines(
            {"host": "a.example.com", "a": ["1.1.1.1"]},
            {"host": "b.example.com", "a": ["1.1.1.1"], "aaaa": ["::2"]},
        )
        hosts = DnsEnumOutputParser.parse_hosts(stdout, ["example.com"])
        outputs = DnsEnumOutputParser.build_outputs(hosts, stdout)
        self.assertEqual(
            outputs["discovered_hosts"],
            ["a.example.com | A: 1.1.1.1", "b.example.com | A: 1.1.1.1 | AAAA: ::2"],
        )
        self.assertEqual(outputs["ipv4"], ["1.1.1.1"])
        self.assertEqual(outputs["hostnames"], ["a.example.com", "b.example.com"])
        self.assertEqual(outputs["manual_targets"], "a.example.com,b.example.com")
        self.assertEqual(outputs["action_output"], stdout)

    def test_build_outputs_empty(self):
        outputs = DnsEnumOutputParser.build_outputs([], "  ")
        self.assertEqual(outputs["discovered_hosts"], [])
        self.assertEqual(outputs["manual_targets"], "")
        self.assertNotIn("action_output", outputs)


if __name__ == "__main__":
    unittest.main()
