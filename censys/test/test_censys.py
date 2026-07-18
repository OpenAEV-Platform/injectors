import json
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

    def test_contracts_carry_available_expectations(self):
        contracts = CensysContracts.build_contract()
        for contract in contracts:
            content = json.loads(contract["contract_content"])
            expectations_field = next(
                f for f in content["fields"] if f["key"] == "expectations"
            )
            self.assertNotIn("predefinedExpectations", expectations_field)
            available = expectations_field["availableExpectations"]
            self.assertEqual(len(available), 1)
            self.assertEqual(available[0]["expectation_type"], "VULNERABILITY")
            self.assertEqual(available[0]["expectation_name"], "Not vulnerable")
            self.assertTrue(available[0]["expectation_is_predefined"])


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
    def test_search_hosts_filters_non_ipv4(self, mock_get):
        response = MagicMock()
        response.json.return_value = {
            "result": {
                "hits": [
                    {"ip": "1.2.3.4", "services": [{"port": 80}]},
                    {"ip": "2001:db8::1", "services": [{"port": 8080}]},
                    {"ip": "not-an-ip", "services": [{"port": 22}]},
                ]
            }
        }
        mock_get.return_value = response

        result = self._client().search_hosts("services.port: 443")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["hosts"], ["1.2.3.4"])

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

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_hosts_follows_cursor_pagination(self, mock_get):
        def _page(hits, next_cursor):
            response = MagicMock()
            response.json.return_value = {
                "result": {"hits": hits, "links": {"next": next_cursor}}
            }
            return response

        mock_get.side_effect = [
            _page([{"ip": "1.2.3.4", "services": [{"port": 80}]}], "CURSOR2"),
            _page([{"ip": "5.6.7.8", "services": [{"port": 443}]}], ""),
        ]

        result = self._client().search_hosts("services.port: 80")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["hosts"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(result.outputs["ports"], [80, 443])
        self.assertEqual(mock_get.call_count, 2)
        second_call_params = mock_get.call_args_list[1].kwargs["params"]
        self.assertEqual(second_call_params["cursor"], "CURSOR2")

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_certificates_stops_at_max_pages(self, mock_get):
        response = MagicMock()
        response.json.return_value = {
            "result": {
                "hits": [{"fingerprint_sha256": "abcd"}],
                "links": {"next": "ALWAYS"},
            }
        }
        mock_get.return_value = response

        client = CensysClient(api_id="id", api_secret="secret", max_pages=3)
        result = client.search_certificates("names: example.com")
        self.assertTrue(result.success)
        self.assertEqual(mock_get.call_count, 3)


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

    @patch("censys_injector.client.censys_client.requests.get")
    def test_search_hosts_invalid_json_body(self, mock_get):
        # requests>=2.27 raises requests.exceptions.JSONDecodeError (a
        # RequestException subclass) from response.json(), so a non-JSON body
        # must surface as a failed result instead of propagating.
        response = MagicMock()
        response.json.side_effect = requests.exceptions.JSONDecodeError(
            "Expecting value", "<html>not json</html>", 0
        )
        mock_get.return_value = response

        result = self._client().search_hosts("services.port: 443")
        self.assertFalse(result.success)
        self.assertIn("Censys request error", result.message)
        self.assertEqual(result.outputs, {})
