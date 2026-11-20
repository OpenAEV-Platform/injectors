import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import dns_enum.openaev_dns_enum as module


def _message(**content):
    content.setdefault("domains", "example.com")
    return {
        "injection": {
            "inject_id": "inject-1",
            "inject_injector_contract": {"injector_contract_id": "contract-1"},
            "inject_content": content,
        }
    }


def _completed(stdout: str):
    return MagicMock(stdout=stdout.encode())


DNSX = "\n".join(
    [
        json.dumps({"host": "www.example.com", "a": ["1.1.1.1"]}),
        json.dumps({"host": "api.example.com", "a": ["2.2.2.2"]}),
    ]
)


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "OpenAEVConfigHelper")
@patch.object(module, "ConfigLoader")
@patch.object(module, "open", create=True)
class TestOpenAEVDnsEnum(unittest.TestCase):
    def _injector(self, m_helper):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        with patch.object(module, "SignatureManager"):
            injector = module.OpenAEVDnsEnum()
        injector.signature_manager = MagicMock()
        return injector

    def _final_callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args_list[-1].kwargs[
            "data"
        ]

    @patch.object(module.subprocess, "run")
    def test_passive_and_resolution_without_endpoint_import(
        self, m_run, _open, _loader, _config, m_helper, _dump
    ):
        injector = self._injector(m_helper)
        m_run.side_effect = [
            _completed("www.example.com\napi.example.com\nevil.org\n"),
            _completed(DNSX),
        ]
        injector.process_message(_message())

        self.assertEqual(m_run.call_count, 2)
        self.assertEqual(m_run.call_args_list[0].args[0][0], "subfinder")
        self.assertEqual(m_run.call_args_list[1].args[0][0], "dnsx")
        data = self._final_callback(injector)
        self.assertEqual(data["execution_status"], "SUCCESS")
        self.assertIn("2 hosts resolved out of 3 candidates", data["execution_message"])
        self.assertIn("no endpoint created", data["execution_message"])
        outputs = json.loads(data["execution_output_structured"])
        self.assertEqual(outputs["hostnames"], ["api.example.com", "www.example.com"])
        self.assertEqual(outputs["manual_targets"], "api.example.com,www.example.com")
        injector.helper.api.endpoint.upsert.assert_not_called()
        injector.helper.api.tag.upsert.assert_not_called()
        injector.signature_manager.send_signatures.assert_called_once()

    @patch.object(module.subprocess, "run")
    def test_endpoint_import_when_option_on(
        self, m_run, _open, _loader, _config, m_helper, _dump
    ):
        injector = self._injector(m_helper)
        injector.helper.api.tag.upsert.return_value = {"tag_id": "tag-1"}
        injector.helper.api.endpoint.upsert.side_effect = [
            {"asset_id": "asset-1"},
            {"asset_id": "asset-2"},
        ]
        m_run.side_effect = [_completed(DNSX)]
        injector.process_message(_message(passive_sources=False, create_endpoints=True))

        self.assertEqual(m_run.call_count, 1)
        self.assertEqual(injector.helper.api.endpoint.upsert.call_count, 2)
        data = self._final_callback(injector)
        self.assertIn("2 endpoints created or updated", data["execution_message"])

    @patch.object(module.subprocess, "run")
    def test_tool_failure_is_reported(
        self, m_run, _open, _loader, _config, m_helper, _dump
    ):
        injector = self._injector(m_helper)
        m_run.side_effect = subprocess.CalledProcessError(2, ["dnsx"], stderr=b"bad")
        injector.process_message(_message(passive_sources=False))
        data = self._final_callback(injector)
        self.assertEqual(data["execution_status"], "ERROR")
        self.assertEqual(data["execution_message"], "bad")
        self.assertNotIn("execution_output_structured", data)

    @patch.object(module.subprocess, "run")
    def test_invalid_domain_fails_before_execution(
        self, m_run, _open, _loader, _config, m_helper, _dump
    ):
        injector = self._injector(m_helper)
        injector.process_message(_message(domains="example.com;rm -rf /"))
        m_run.assert_not_called()
        data = self._final_callback(injector)
        self.assertEqual(data["execution_status"], "ERROR")
        self.assertIn("Invalid root domain", data["execution_message"])


if __name__ == "__main__":
    unittest.main()
