import importlib.util
from unittest import TestCase, skipUnless

from teams import contracts_teams as ct

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None


@skipUnless(_HAS_PYOAEV, "pyoaev is required to build contracts")
class TeamsContractsTest(TestCase):
    def _contract_content(self):
        import json

        contracts = ct.TeamsContracts.build()
        self.assertEqual(len(contracts), 1)
        return json.loads(contracts[0]["contract_content"])

    def test_single_contract_with_stable_id(self):
        contracts = ct.TeamsContracts.build()
        self.assertEqual(contracts[0]["contract_id"], ct.CONTRACT_ID)

    def test_target_type_selector_defaults_to_channel(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        target = fields[ct.KEY_TARGET_TYPE]
        self.assertEqual(target["type"], "select")
        self.assertEqual(target["defaultValue"], [ct.TARGET_CHANNEL])
        self.assertEqual(
            set(target["choices"].keys()), {ct.TARGET_CHANNEL, ct.TARGET_CHAT}
        )

    def test_channel_fields_visible_only_for_channel_target(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        for key in (ct.KEY_TEAM_ID, ct.KEY_CHANNEL_ID):
            self.assertEqual(
                fields[key]["visibleConditionValues"],
                {ct.KEY_TARGET_TYPE: ct.TARGET_CHANNEL},
                msg=f"{key} should be visible only for channel targets",
            )

    def test_chat_field_visible_only_for_chat_target(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        self.assertEqual(
            fields[ct.KEY_CHAT_ID]["visibleConditionValues"],
            {ct.KEY_TARGET_TYPE: ct.TARGET_CHAT},
        )

    def test_card_json_visible_only_for_card_format(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        self.assertEqual(
            fields[ct.KEY_CARD_JSON]["visibleConditionValues"],
            {ct.KEY_CONTENT_TYPE: ct.CONTENT_CARD},
        )

    def test_title_and_message_are_mandatory(self):
        fields = {f["key"]: f for f in self._contract_content()["fields"]}
        self.assertTrue(fields[ct.KEY_TITLE]["mandatory"])
        self.assertTrue(fields[ct.KEY_MESSAGE]["mandatory"])
