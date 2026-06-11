import unittest

import nmap.contracts.nmap_contracts as module


class TestNmapContracts(unittest.TestCase):
    def test_nmap_contracts(self):
        prepared_contracts = module.NmapContracts.build_contract()

        self.assertEqual(len(prepared_contracts), 3)
