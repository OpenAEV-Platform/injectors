import importlib.util
from unittest import TestCase, skipUnless

from ai_redteam.contracts import constants as c

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class BuildContractsTest(TestCase):
    def test_builds_one_contract_per_technique(self):
        from ai_redteam.contracts.ai_contracts import build_contracts

        contracts = build_contracts()
        self.assertEqual(len(contracts), len(c.ALL_TECHNIQUES))
