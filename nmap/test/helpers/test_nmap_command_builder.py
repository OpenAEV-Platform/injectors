import unittest
from unittest.mock import sentinel

import nmap.helpers.nmap_command_builder as module


class TestNmapCommandBuilder(unittest.TestCase):
    def test_build_args_tcp_syn_scan(self):
        contract_id = module.TCP_SYN_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sS", "-oX", "-", sentinel.target],
        )
    def test_build_args_tcp_connect_scan(self):
        contract_id = module.TCP_CONNECT_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sT", "-oX", "-", sentinel.target],
        )
    def test_build_args_fin_scan(self):
        contract_id = module.FIN_SCAN_CONTRACT
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-sF", "-oX", "-", sentinel.target],
        )
    def test_build_args_other(self):
        contract_id = sentinel.contract_id
        targets = [sentinel.target]

        args = module.NmapCommandBuilder.build_args(contract_id, targets)

        self.assertEqual(
            args,
            ["nmap", "-Pn", "-oX", "-", sentinel.target],
        )
