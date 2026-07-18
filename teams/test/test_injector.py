import importlib.util
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock

from teams.client.teams_client import ExecutionResult
from teams.contracts_teams import (
    CONTRACT_ID,
    KEY_CHANNEL_ID,
    KEY_CHAT_ID,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TARGET_TYPE,
    KEY_TEAM_ID,
    KEY_TITLE,
    TARGET_CHANNEL,
    TARGET_CHAT,
)

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None

if _HAS_PYOAEV:
    from teams.openaev_teams import OpenAEVTeamsInjector


def _data(contract_id=CONTRACT_ID, content=None):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content or {},
        }
    }


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ExecuteRoutingTest(TestCase):
    def _injector(self):
        obj = OpenAEVTeamsInjector.__new__(OpenAEVTeamsInjector)
        obj.client = MagicMock()
        obj.client.post_channel_message.return_value = ExecutionResult(
            success=True, message="ok"
        )
        obj.client.post_chat_message.return_value = ExecutionResult(
            success=True, message="ok"
        )
        return obj

    def test_rejects_unknown_contract(self):
        obj = self._injector()
        with self.assertRaises(ValueError):
            obj.execute(_data(contract_id="other"))

    def test_routes_channel_message(self):
        obj = self._injector()
        content = {
            KEY_TARGET_TYPE: TARGET_CHANNEL,
            KEY_TEAM_ID: "team-1",
            KEY_CHANNEL_ID: "channel-1",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        result = obj.execute(_data(content=content))
        self.assertTrue(result.success)
        obj.client.post_channel_message.assert_called_once()
        args = obj.client.post_channel_message.call_args.args
        self.assertEqual(args[0], "team-1")
        self.assertEqual(args[1], "channel-1")

    def test_channel_message_requires_ids(self):
        obj = self._injector()
        content = {
            KEY_TARGET_TYPE: TARGET_CHANNEL,
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        with self.assertRaises(ValueError):
            obj.execute(_data(content=content))

    def test_routes_chat_message(self):
        obj = self._injector()
        content = {
            KEY_TARGET_TYPE: TARGET_CHAT,
            KEY_CHAT_ID: "19:chat@thread.v2",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        result = obj.execute(_data(content=content))
        self.assertTrue(result.success)
        obj.client.post_chat_message.assert_called_once()
        args = obj.client.post_chat_message.call_args.args
        self.assertEqual(args[0], "19:chat@thread.v2")
        # The second argument is the Graph message body built from the content.
        self.assertIn("body", args[1])

    def test_chat_message_requires_chat_id(self):
        obj = self._injector()
        content = {
            KEY_TARGET_TYPE: TARGET_CHAT,
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        with self.assertRaises(ValueError):
            obj.execute(_data(content=content))


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ProcessMessageTest(TestCase):
    def _injector(self):
        obj = OpenAEVTeamsInjector.__new__(OpenAEVTeamsInjector)
        obj.helper = MagicMock()
        obj.client = MagicMock()
        return obj

    def test_reports_success(self):
        obj = self._injector()
        obj.client.post_channel_message.return_value = ExecutionResult(
            success=True, message="sent"
        )
        content = {
            KEY_TARGET_TYPE: TARGET_CHANNEL,
            KEY_TEAM_ID: "t",
            KEY_CHANNEL_ID: "c",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        obj.process_message(_data(content=content))
        obj.helper.api.inject.execution_reception.assert_called_once()
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "SUCCESS")

    def test_reports_error_on_exception(self):
        obj = self._injector()
        content = {KEY_TARGET_TYPE: TARGET_CHANNEL, KEY_TITLE: "t", KEY_MESSAGE: "m"}
        obj.process_message(_data(content=content))
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")
