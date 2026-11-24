import unittest

from dns_enum.models.data import (
    MessageData,
    parse_domains,
    parse_record_types,
    parse_wordlist,
)


def _data(**content):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": "contract-1"},
            "inject_content": content,
        }
    }


class TestParsers(unittest.TestCase):
    def test_parse_domains_normalises_and_dedupes(self):
        self.assertEqual(
            parse_domains(" Example.com. , *.example.org,example.com,, "),
            ["example.com", "example.org"],
        )

    def test_parse_domains_refuses_injection_and_empty(self):
        for raw in ["example.com;id", "-x.com", "localhost", "a b.com", "--help"]:
            with self.assertRaises(ValueError):
                parse_domains(raw)
        with self.assertRaises(ValueError):
            parse_domains(" , ")

    def test_parse_record_types(self):
        self.assertEqual(parse_record_types(["txt", "A"]), ["A", "TXT"])
        self.assertEqual(parse_record_types("mx,ns"), ["MX", "NS"])
        self.assertEqual(parse_record_types([]), ["A", "AAAA", "CNAME"])
        with self.assertRaises(ValueError):
            parse_record_types(["PTR"])

    def test_parse_wordlist(self):
        self.assertEqual(
            parse_wordlist("www\nAPI\n\n-bad\nwww\ndev.int, mail"),
            ["www", "api", "dev.int", "mail"],
        )


class TestMessageData(unittest.TestCase):
    def test_defaults(self):
        msg = MessageData(_data(domains="example.com"))
        self.assertEqual(msg.inject_id, "inject-1")
        self.assertEqual(msg.domains, ["example.com"])
        self.assertTrue(msg.passive_sources)
        self.assertEqual(msg.record_types, ["A", "AAAA", "CNAME"])
        self.assertFalse(msg.brute_force)
        self.assertEqual(msg.wordlist, [])
        self.assertEqual(msg.rate_limit, 100)
        self.assertEqual(msg.timeout, 600)
        self.assertFalse(msg.create_endpoints)
        self.assertEqual(msg.endpoint_tag, "discovered:dns")
        self.assertIsNone(msg.asset_group_id)
        self.assertTrue(msg.classify_assets)

    def test_options(self):
        msg = MessageData(
            _data(
                domains="example.com",
                passive_sources="false",
                record_types=["MX"],
                brute_force=True,
                wordlist="www",
                rate_limit="5000",
                timeout="30",
                create_endpoints="true",
                endpoint_tag="ext",
                asset_group_id=" group-1 ",
                classify_assets="false",
                expectations=[{"expectation_type": "DETECTION"}, {}],
            )
        )
        self.assertFalse(msg.passive_sources)
        self.assertEqual(msg.record_types, ["MX"])
        self.assertEqual(msg.wordlist, ["www"])
        self.assertEqual(msg.rate_limit, 1000)
        self.assertEqual(msg.timeout, 30)
        self.assertTrue(msg.create_endpoints)
        self.assertEqual(msg.endpoint_tag, "ext")
        self.assertEqual(msg.endpoint_tags, ["ext"])
        self.assertEqual(msg.asset_group_id, "group-1")
        self.assertFalse(msg.classify_assets)
        self.assertEqual(msg.expectation_types, ["DETECTION"])

    def test_several_endpoint_tags(self):
        msg = MessageData(
            _data(domains="example.com", endpoint_tag=" ext , internet,ext,, ")
        )
        self.assertEqual(msg.endpoint_tags, ["ext", "internet"])
        self.assertEqual(
            MessageData(_data(domains="example.com", endpoint_tag=" , ")).endpoint_tags,
            ["discovered:dns"],
        )

    def test_invalid_values(self):
        with self.assertRaises(ValueError):
            MessageData(_data(domains="example.com", brute_force=True, wordlist=""))
        with self.assertRaises(ValueError):
            MessageData(_data(domains="example.com", timeout="abc"))
        with self.assertRaises(ValueError):
            MessageData(_data(domains="example.com", rate_limit="0"))


if __name__ == "__main__":
    unittest.main()
