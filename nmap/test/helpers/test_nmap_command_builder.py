import unittest
from unittest.mock import sentinel

import nmap.helpers.nmap_command_builder as module

TAIL = ["--reason", "-oX", "-"]


class TestNmapCommandBuilder(unittest.TestCase):
    def test_build_args_tcp_syn_scan(self):
        contract_id = module.TCP_SYN_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sS", *TAIL, sentinel.target],
        )

    def test_build_args_tcp_connect_scan(self):
        contract_id = module.TCP_CONNECT_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sT", *TAIL, sentinel.target],
        )

    def test_build_args_fin_scan(self):
        contract_id = module.FIN_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sF", *TAIL, sentinel.target],
        )

    def test_build_args_tcp_syn_version_scan(self):
        contract_id = module.TCP_SYN_VERSION_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sS", "-sV", *TAIL, sentinel.target],
        )

    def test_default_contracts_do_not_detect_versions(self):
        for contract_id in (
            module.TCP_SYN_SCAN_CONTRACT,
            module.TCP_CONNECT_SCAN_CONTRACT,
            module.FIN_SCAN_CONTRACT,
        ):
            args = module.NmapCommandBuilder.build_args(contract_id, ["10.0.0.5"])
            self.assertNotIn("-sV", args)

    def test_build_args_other(self):
        contract_id = sentinel.contract_id
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", *TAIL, sentinel.target],
        )


class TestNmapTuningOptions(unittest.TestCase):
    def build(self, **options):
        return module.NmapCommandBuilder.build_args(
            module.TCP_SYN_SCAN_CONTRACT, ["10.0.0.5"], options
        )

    def test_empty_options_keep_the_default_command(self):
        self.assertEqual(
            self.build(timing_template=["default"], max_retries="", ports=None),
            ["nmap", "-Pn", "-sS", *TAIL, "10.0.0.5"],
        )

    def test_every_option_reaches_the_command(self):
        self.assertEqual(
            self.build(
                timing_template=["T4"],
                max_retries="1",
                host_timeout_seconds="60",
                max_rtt_timeout_ms="500",
                min_rate="300",
                top_ports="100",
            ),
            [
                "nmap",
                "-Pn",
                "-sS",
                "-T4",
                "--max-retries",
                "1",
                "--host-timeout",
                "60s",
                "--max-rtt-timeout",
                "500ms",
                "--min-rate",
                "300",
                "--top-ports",
                "100",
                *TAIL,
                "10.0.0.5",
            ],
        )

    def test_port_list(self):
        args = self.build(ports="22, 80,443,8000-8100")
        self.assertEqual(args[args.index("-p") + 1], "22,80,443,8000-8100")

    def test_invalid_values_are_refused(self):
        for options in (
            {"timing_template": "T9"},
            {"max_retries": "-1"},
            {"max_retries": "1; rm -rf /"},
            {"host_timeout_seconds": "1h"},
            {"min_rate": "999999999"},
            {"top_ports": "0"},
            {"ports": "22 -sV --script=x"},
            {"ports": "70000"},
            {"ports": "22", "top_ports": "100"},
        ):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    self.build(**options)
