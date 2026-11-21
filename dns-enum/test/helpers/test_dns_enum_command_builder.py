import unittest

from dns_enum.helpers.dns_enum_command_builder import DnsEnumCommandBuilder


class TestDnsEnumCommandBuilder(unittest.TestCase):
    def test_subfinder_args(self):
        self.assertEqual(
            DnsEnumCommandBuilder.subfinder_args("/tmp/d.txt", 50, 600),
            [
                "subfinder",
                "-dL",
                "/tmp/d.txt",
                "-silent",
                "-duc",
                "-rl",
                "50",
                "-max-time",
                "10",
            ],
        )
        self.assertEqual(DnsEnumCommandBuilder.subfinder_args("f", 1, 30)[-1], "1")

    def test_passive_budget_is_half_the_timeout(self):
        self.assertEqual(DnsEnumCommandBuilder.passive_budget(600), 300)
        self.assertEqual(DnsEnumCommandBuilder.passive_budget(1), 1)

    def test_dnsx_args(self):
        self.assertEqual(
            DnsEnumCommandBuilder.dnsx_args("/tmp/h.txt", ["A", "CNAME", "TXT"], 100),
            [
                "dnsx",
                "-l",
                "/tmp/h.txt",
                "-silent",
                "-json",
                "-duc",
                "-a",
                "-cname",
                "-txt",
                "-rl",
                "100",
            ],
        )

    def test_brute_force_candidates(self):
        self.assertEqual(
            DnsEnumCommandBuilder.brute_force_candidates(
                ["a.com", "b.com"], ["www", "api"]
            ),
            ["www.a.com", "api.a.com", "www.b.com", "api.b.com"],
        )


if __name__ == "__main__":
    unittest.main()
