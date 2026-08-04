import json
import unittest
from unittest.mock import MagicMock, patch

import http_query.openaev_http as module


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "ConfigLoader")
class ProcessMessageActionOutputTest(unittest.TestCase):
    """execution_outputs["action_output"] is the raw HTTP response body, routed
    independently of the "url" output — present whenever the response has a
    body, absent otherwise (nothing to route)."""

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
        """Matches the non-blank check nmap/nuclei use for the same field."""
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


if __name__ == "__main__":
    unittest.main()
