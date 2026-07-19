import importlib.util
import json
from unittest import TestCase, skipUnless

from email_gws_injector import contracts_email_gws as ec

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class EmailGWSContractsTest(TestCase):
    def _contract_content(self):
        contracts = ec.EmailGWSContracts.build()
        self.assertEqual(len(contracts), 1)
        return json.loads(contracts[0]["contract_content"])

    def test_single_contract_with_stable_id(self):
        contracts = ec.EmailGWSContracts.build()
        self.assertEqual(contracts[0]["contract_id"], ec.CONTRACT_ID)

    def test_body_format_defaults_to_html(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        body_format = fields[ec.KEY_BODY_FORMAT]
        self.assertEqual(body_format["type"], "select")
        self.assertEqual(body_format["defaultValue"], [ec.BODY_FORMAT_HTML])
        self.assertEqual(
            set(body_format["choices"].keys()),
            {ec.BODY_FORMAT_HTML, ec.BODY_FORMAT_TEXT},
        )

    def test_core_fields_are_mandatory(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        for key in (ec.KEY_FROM, ec.KEY_TO, ec.KEY_SUBJECT, ec.KEY_BODY):
            self.assertTrue(fields[key]["mandatory"], msg=f"{key} should be mandatory")

    def test_optional_fields_are_not_mandatory(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        for key in (ec.KEY_CC, ec.KEY_BCC, ec.KEY_REPLY_TO):
            self.assertFalse(fields[key]["mandatory"], msg=f"{key} should be optional")
