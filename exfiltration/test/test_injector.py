import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import exfiltration_injector.openaev_exfiltration as mod
from exfiltration_injector.contracts_exfiltration import (
    CLOUD_EXFIL_CONTRACT,
    DNS_EXFIL_CONTRACT,
    HTTPS_EXFIL_CONTRACT,
    MAX_SIZE_KB,
    MIN_SIZE_KB,
)
from exfiltration_injector.helpers.exfiltration_executor import ExfilResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "exfiltration--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVExfiltration()
    injector.helper = MagicMock()
    return injector


def _data(contract_id, content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_dns_dispatch(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.exfiltrate_dns.return_value = ExfilResult(True, "sent")
        injector.process_message(
            _data(DNS_EXFIL_CONTRACT, {"dns_domain": "x.example", "size_kb": ["64"]})
        )
        injector.executor.exfiltrate_dns.assert_called_once()
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_https_dispatch(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.exfiltrate_https.return_value = ExfilResult(True, "sent")
        injector.process_message(
            _data(HTTPS_EXFIL_CONTRACT, {"https_url": "https://c2", "size_kb": "bad"})
        )
        injector.executor.exfiltrate_https.assert_called_once()

    def test_cloud_dispatch(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.exfiltrate_cloud.return_value = ExfilResult(True, "sent")
        injector.process_message(
            _data(CLOUD_EXFIL_CONTRACT, {"cloud_url": "https://bucket"})
        )
        injector.executor.exfiltrate_cloud.assert_called_once()

    def test_unknown_contract_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data("nope", {}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_missing_required_field_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data(HTTPS_EXFIL_CONTRACT, {"size_kb": ["64"]}))
        injector.executor.exfiltrate_https.assert_not_called()
        callback = self._callback(injector)
        self.assertEqual(callback["execution_status"], "ERROR")
        self.assertIn("https_url", callback["execution_message"])

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class SizeParsingTest(TestCase):
    def test_size_clamps_above_max(self):
        self.assertEqual(
            mod.OpenAEVExfiltration._size({"size_kb": "9999999"}), MAX_SIZE_KB
        )

    def test_size_clamps_below_min(self):
        self.assertEqual(mod.OpenAEVExfiltration._size({"size_kb": "0"}), MIN_SIZE_KB)
        self.assertEqual(mod.OpenAEVExfiltration._size({"size_kb": "-5"}), MIN_SIZE_KB)

    def test_size_defaults_when_invalid(self):
        self.assertEqual(mod.OpenAEVExfiltration._size({"size_kb": "bad"}), 64)
        self.assertEqual(mod.OpenAEVExfiltration._size({}), 64)

    def test_size_accepts_valid_list_shape(self):
        self.assertEqual(mod.OpenAEVExfiltration._size({"size_kb": ["256"]}), 256)
