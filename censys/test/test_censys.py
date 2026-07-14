from unittest import TestCase
from unittest.mock import MagicMock, patch

import requests
from censys_injector.client.censys_client import CensysClient
from censys_injector.contracts_censys import (
    CERT_SEARCH_CONTRACT,
    HOST_SEARCH_CONTRACT,
    CensysContracts,
)


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = CensysContracts.build_contract()
        ids = {c["contract_id"] for c in contracts}
        self.assertEqual(ids, {HOST_SEARCH_CONTRACT, CERT_SEARCH_CONTRACT})


class ClientParsingTest(TestCase):
    def _client(self):
        return CensysClient(api_id="id", api_secret="secret")

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_hosts_parses_hits(self, mock_get):
        response = MagicMock()
        response.json.return_value = {
            "result": {
                "hits": [
                    {"ip": "1.2.3.4", "services": [{"port": 443}, {"port": 80}]},
                    {"ip": "5.6.7.8", "services": [{"port": 443}]},
                ]
            }
        }
        mock_get.return_value = response

        result = self._client().search_hosts("services.port: 443")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["hosts"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(result.outputs["ports"], [80, 443])

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_certificates_parses_fingerprints(self, mock_get):
        response = MagicMock()
        response.json.return_value = {
            "result": {"hits": [{"fingerprint_sha256": "abcd"}]}
        }
        mock_get.return_value = response

        result = self._client().search_certificates("names: example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["certificates"], ["abcd"])


class ClientErrorHandlingTest(TestCase):
    def _client(self, logger=None):
        return CensysClient(api_id="id", api_secret="secret", logger=logger)

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_hosts_http_error(self, mock_get):
        response = MagicMock()
        response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
        mock_get.return_value = response

        logger = MagicMock()
        result = self._client(logger).search_hosts("services.port: 443")
        self.assertFalse(result.success)
        self.assertIn("Censys host search failed", result.message)
        self.assertEqual(result.outputs, {})
        logger.error.assert_called_once()

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_hosts_request_exception(self, mock_get):
        mock_get.side_effect = requests.ConnectionError("connection refused")

        result = self._client().search_hosts("services.port: 443")
        self.assertFalse(result.success)
        self.assertIn("Censys request error", result.message)
        self.assertEqual(result.outputs, {})

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_certificates_http_error(self, mock_get):
        response = MagicMock()
        response.raise_for_status.side_effect = requests.HTTPError("429 Too Many")
        mock_get.return_value = response

        result = self._client().search_certificates("names: example.com")
        self.assertFalse(result.success)
        self.assertIn("Censys certificate search failed", result.message)
        self.assertEqual(result.outputs, {})

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_certificates_request_exception(self, mock_get):
        mock_get.side_effect = requests.Timeout("timed out")

        result = self._client().search_certificates("names: example.com")
        self.assertFalse(result.success)
        self.assertIn("Censys request error", result.message)
        self.assertEqual(result.outputs, {})
