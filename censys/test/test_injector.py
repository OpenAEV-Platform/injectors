import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import censys_injector.openaev_censys as mod
from censys_injector.client.censys_client import CensysResult
from censys_injector.contracts_censys import (
    CERT_SEARCH_CONTRACT,
    HOST_SEARCH_CONTRACT,
)

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "censys--test",
    "CENSYS_API_ID": "api-id",
    "CENSYS_API_SECRET": "api-secret",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVCensys()
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

    def test_host_search_success(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.client.search_hosts.return_value = CensysResult(
            True, "found", {"hosts": ["1.2.3.4"]}
        )
        injector.process_message(_data(HOST_SEARCH_CONTRACT, {"query": "x"}))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        injector.client.search_hosts.assert_called_once()

    def test_certificate_search_success(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.client.search_certificates.return_value = CensysResult(
            True, "found", {"certificates": ["abcd"]}
        )
        injector.process_message(_data(CERT_SEARCH_CONTRACT, {"query": "x"}))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")
        injector.client.search_certificates.assert_called_once()

    def test_missing_query_reports_error(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.process_message(_data(HOST_SEARCH_CONTRACT, {}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_unknown_contract_reports_error(self):
        injector = make_injector()
        injector.client = MagicMock()
        injector.process_message(_data("nope", {"query": "x"}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()
