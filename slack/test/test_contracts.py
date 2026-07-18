import importlib.util
import json
from unittest import TestCase, skipUnless

from slack_injector import contracts_slack as sc

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class SlackContractsTest(TestCase):
    def _contract_content(self):
        contracts = sc.SlackContracts.build()
        self.assertEqual(len(contracts), 1)
        return json.loads(contracts[0]["contract_content"])

    def test_single_contract_with_stable_id(self):
        contracts = sc.SlackContracts.build()
        self.assertEqual(contracts[0]["contract_id"], sc.CONTRACT_ID)

    def test_content_type_selector_defaults_to_blocks(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        content = fields[sc.KEY_CONTENT_TYPE]
        self.assertEqual(content["type"], "select")
        self.assertEqual(content["defaultValue"], [sc.CONTENT_BLOCKS])
        self.assertEqual(
            set(content["choices"].keys()), {sc.CONTENT_BLOCKS, sc.CONTENT_TEXT}
        )

    def test_blocks_json_visible_only_for_block_kit(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        self.assertEqual(
            fields[sc.KEY_BLOCKS_JSON]["visibleConditionValues"],
            {sc.KEY_CONTENT_TYPE: sc.CONTENT_BLOCKS},
        )

    def test_channel_title_message_are_mandatory(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        for key in (sc.KEY_CHANNEL, sc.KEY_TITLE, sc.KEY_MESSAGE):
            self.assertTrue(fields[key]["mandatory"], msg=f"{key} should be mandatory")
