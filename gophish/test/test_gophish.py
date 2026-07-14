from unittest import TestCase
from unittest.mock import MagicMock, patch

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

    @patch("gophish_injector.client.gophish_client.requests.get")
    def test_get_stats(self, mock_get):
        response = MagicMock()
        response.json.return_value = {"stats": {"clicked": 5}}
        mock_get.return_value = response

        client = GophishClient("https://gophish:3333", "key")
        result = client.get_campaign_stats(7)
        self.assertTrue(result.success)
        self.assertEqual(result.stats["clicked"], 5)
