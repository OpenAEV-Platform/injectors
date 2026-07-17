from unittest import TestCase
from unittest.mock import MagicMock, patch

import requests
from gophish_injector.client.gophish_client import GophishClient
from gophish_injector.contracts_gophish import (
    GOPHISH_CAMPAIGN_CONTRACT,
    GophishContracts,
)


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = GophishContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], GOPHISH_CAMPAIGN_CONTRACT)


class ClientTest(TestCase):
    @patch("gophish_injector.client.gophish_client.requests.post")
    def test_create_campaign_success(self, mock_post):
        response = MagicMock()
        response.json.return_value = {
            "id": 7,
            "stats": {
                "total": 10,
                "sent": 10,
                "opened": 3,
                "clicked": 1,
                "submitted_data": 0,
            },
        }
        mock_post.return_value = response

        client = GophishClient("https://gophish:3333", "key")
        result = client.create_campaign(
            name="c",
            template_name="t",
            page_name="p",
            smtp_name="s",
            group_name="g",
            url="http://phish",
        )
        self.assertTrue(result.success)
        self.assertEqual(result.campaign_id, 7)
        self.assertEqual(result.stats["opened"], 3)
        sent_payload = mock_post.call_args.kwargs["json"]
        self.assertIn("launch_date", sent_payload)
        self.assertTrue(sent_payload["launch_date"])
        self.assertEqual(sent_payload["groups"], [{"name": "g"}])

    @patch("gophish_injector.client.gophish_client.requests.post")
    def test_create_campaign_verify_tls_default(self, mock_post):
        response = MagicMock()
        response.json.return_value = {"id": 1, "stats": {}}
        mock_post.return_value = response

        client = GophishClient("https://gophish:3333", "key")
        client.create_campaign(
            name="c",
            template_name="t",
            page_name="p",
            smtp_name="s",
            group_name="g",
            url="http://phish",
        )
        self.assertTrue(mock_post.call_args.kwargs["verify"])

    @patch("gophish_injector.client.gophish_client.requests.get")
    def test_get_stats(self, mock_get):
        response = MagicMock()
        response.json.return_value = {"stats": {"clicked": 5}}
        mock_get.return_value = response

        client = GophishClient("https://gophish:3333", "key")
        result = client.get_campaign_stats(7)
        self.assertTrue(result.success)
        self.assertEqual(result.stats["clicked"], 5)

    @patch("gophish_injector.client.gophish_client.requests.post")
    def test_create_campaign_http_error_includes_body_and_logs(self, mock_post):
        error_response = MagicMock()
        error_response.text = "Template not found"
        http_error = requests.HTTPError("400 Client Error")
        http_error.response = error_response
        response = MagicMock()
        response.raise_for_status.side_effect = http_error
        mock_post.return_value = response

        logger = MagicMock()
        client = GophishClient("https://gophish:3333", "key", logger=logger)
        result = client.create_campaign(
            name="c",
            template_name="t",
            page_name="p",
            smtp_name="s",
            group_name="g",
            url="http://phish",
        )
        self.assertFalse(result.success)
        self.assertIn("Template not found", result.message)
        logger.error.assert_called_once()

    @patch("gophish_injector.client.gophish_client.requests.get")
    def test_get_stats_http_error_includes_body(self, mock_get):
        error_response = MagicMock()
        error_response.text = "campaign not found"
        http_error = requests.HTTPError("404 Client Error")
        http_error.response = error_response
        response = MagicMock()
        response.raise_for_status.side_effect = http_error
        mock_get.return_value = response

        client = GophishClient("https://gophish:3333", "key")
        result = client.get_campaign_stats(7)
        self.assertFalse(result.success)
        self.assertIn("campaign not found", result.message)
