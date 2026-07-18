import importlib.util
from unittest import TestCase, skipUnless
from unittest.mock import MagicMock

from slack_injector.client.slack_client import ExecutionResult
from slack_injector.contracts_slack import (
    CONTRACT_ID,
    KEY_CHANNEL,
    KEY_CONTENT_TYPE,
    KEY_MESSAGE,
    KEY_TITLE,
)

_HAS_PYOAEV = importlib.util.find_spec("pyoaev") is not None

if _HAS_PYOAEV:
    from slack_injector.openaev_slack import OpenAEVSlackInjector


def _data(contract_id=CONTRACT_ID, content=None):
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content or {},
        }
    }


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ExecuteTest(TestCase):
    def _injector(self):
        obj = OpenAEVSlackInjector.__new__(OpenAEVSlackInjector)
        obj.client = MagicMock()
        obj.client.post_message.return_value = ExecutionResult(
            success=True, message="ok"
        )
        return obj

    def test_rejects_unknown_contract(self):
        obj = self._injector()
        with self.assertRaises(ValueError):
            obj.execute(_data(contract_id="other"))

    def test_requires_channel(self):
        obj = self._injector()
        content = {KEY_CONTENT_TYPE: "text", KEY_TITLE: "t", KEY_MESSAGE: "m"}
        with self.assertRaises(ValueError):
            obj.execute(_data(content=content))

    def test_posts_message(self):
        obj = self._injector()
        content = {
            KEY_CHANNEL: "C123",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        result = obj.execute(_data(content=content))
        self.assertTrue(result.success)
        obj.client.post_message.assert_called_once()
        payload = obj.client.post_message.call_args.args[0]
        self.assertEqual(payload["channel"], "C123")


@skipUnless(_HAS_PYOAEV, "pyoaev is required to import the injector entrypoint")
class ProcessMessageTest(TestCase):
    def _injector(self):
        obj = OpenAEVSlackInjector.__new__(OpenAEVSlackInjector)
        obj.helper = MagicMock()
        obj.client = MagicMock()
        return obj

    def test_reports_success(self):
        obj = self._injector()
        obj.client.post_message.return_value = ExecutionResult(
            success=True, message="sent"
        )
        content = {
            KEY_CHANNEL: "C1",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        obj.process_message(_data(content=content))
        obj.helper.api.inject.execution_reception.assert_called_once()
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "SUCCESS")

    def test_reports_error_when_slack_fails(self):
        obj = self._injector()
        obj.client.post_message.return_value = ExecutionResult(
            success=False, message="Slack API error: channel_not_found"
        )
        content = {
            KEY_CHANNEL: "bad",
            KEY_CONTENT_TYPE: "text",
            KEY_TITLE: "t",
            KEY_MESSAGE: "m",
        }
        obj.process_message(_data(content=content))
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")

    def test_reports_error_on_exception(self):
        obj = self._injector()
        content = {KEY_CONTENT_TYPE: "text", KEY_TITLE: "t", KEY_MESSAGE: "m"}
        obj.process_message(_data(content=content))
        final = obj.helper.api.inject.execution_callback.call_args
        self.assertEqual(final.kwargs["data"]["execution_status"], "ERROR")
