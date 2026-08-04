import json
import unittest
from unittest.mock import MagicMock, patch

import http_query.openaev_http as module


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "ConfigLoader")
class ProcessMessageActionOutputTest(unittest.TestCase):
    """execution_outputs["action_output"] is the raw HTTP response body, routed
    independently of the "url" output - present whenever the response has a
    non-blank body, absent otherwise (nothing to route)."""

    def _build_injector(self, m_configloader, m_helper, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVHttp()
        return injector

    def _run(self, injector, http_execution_result):
        with patch.object(
            injector, "http_execution", return_value=http_execution_result
        ):
            injector.process_message({"injection": {"inject_id": "inj-1"}})
        callback_calls = injector.helper.api.inject.execution_callback.call_args_list
        # last call is the terminal "complete" callback
        return json.loads(
            callback_calls[-1].kwargs["data"]["execution_output_structured"]
        )

    def test_action_output_present_for_non_empty_body(
        self, m_configloader, m_helper, _
    ):
        injector = self._build_injector(m_configloader, m_helper, _)
        outputs = self._run(
            injector,
            {
                "url": "https://example.com",
                "code": 200,
                "status": "SUCCESS",
                "message": "<html>hi</html>",
                "body": "<html>hi</html>",
            },
        )
        self.assertEqual(outputs["action_output"], "<html>hi</html>")
        self.assertEqual(outputs["url"], "https://example.com")

    def test_action_output_absent_for_empty_body(self, m_configloader, m_helper, _):
        injector = self._build_injector(m_configloader, m_helper, _)
        outputs = self._run(
            injector,
            {
                "url": "https://example.com",
                "code": 204,
                "status": "SUCCESS",
                "message": "No response body (HTTP 204)",
                "body": "",
            },
        )
        self.assertNotIn("action_output", outputs)
        self.assertEqual(outputs["url"], "https://example.com")

    def test_action_output_absent_for_whitespace_only_body(
        self, m_configloader, m_helper, _
    ):
        """Same non-blank gate netexec uses for its action_output."""
        injector = self._build_injector(m_configloader, m_helper, _)
        outputs = self._run(
            injector,
            {
                "url": "https://example.com",
                "code": 200,
                "status": "SUCCESS",
                "message": "  \n  ",
                "body": "  \n  ",
            },
        )
        self.assertNotIn("action_output", outputs)

    def test_action_output_preserves_body_verbatim(self, m_configloader, m_helper, _):
        """The body is routed as-is: .strip() only gates the non-blank check,
        it must not mutate the stored response content."""
        injector = self._build_injector(m_configloader, m_helper, _)
        body = '  {"ok": true}\n'
        outputs = self._run(
            injector,
            {
                "url": "https://example.com",
                "code": 200,
                "status": "SUCCESS",
                "message": body,
                "body": body,
            },
        )
        self.assertEqual(outputs["action_output"], body)

    def test_unsupported_contract_reports_real_error_message(
        self, m_configloader, m_helper, _
    ):
        """http_execution returns an error dict without "url" for unsupported
        contracts; the callback must carry that message (not a KeyError repr)
        with the url output falling back to the requested URI."""
        injector = self._build_injector(m_configloader, m_helper, _)
        injector.process_message(
            {
                "injection": {
                    "inject_id": "inj-1",
                    "inject_content": {
                        "uri": "https://example.com",
                        "headers": [],
                        "basicAuth": False,
                    },
                    "inject_injector_contract": {
                        "injector_contract_id": "not-a-known-contract"
                    },
                }
            }
        )
        callback_calls = injector.helper.api.inject.execution_callback.call_args_list
        data = callback_calls[-1].kwargs["data"]
        self.assertEqual(data["execution_status"], "ERROR")
        self.assertEqual(
            data["execution_message"], "Selected contract is not supported"
        )
        outputs = json.loads(data["execution_output_structured"])
        self.assertEqual(outputs["url"], "https://example.com")
        self.assertNotIn("action_output", outputs)


if __name__ == "__main__":
    unittest.main()
