import json
from unittest import TestCase

from webapp_injector.contracts_webapp import (
    SQLMAP_CONTRACT,
    ZAP_BASELINE_CONTRACT,
    WebappContracts,
)
from webapp_injector.helpers.webapp_executor import WebappExecutor


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = WebappContracts.build_contract()
        ids = {c["contract_id"] for c in contracts}
        self.assertEqual(ids, {ZAP_BASELINE_CONTRACT, SQLMAP_CONTRACT})

    def test_outputs_are_finding_compatible(self):
        import json

        for contract in WebappContracts.build_contract():
            content = json.loads(contract["contract_content"])
            self.assertTrue(any(o["isFindingCompatible"] for o in content["outputs"]))


class ParsingTest(TestCase):
    def test_parse_zap_report(self):
        raw = (
            '{"site": [{"alerts": [{"alert": "SQL Injection"}, ' '{"alert": "XSS"}]}]}'
        )
        alerts = WebappExecutor._parse_zap_report(raw)
        self.assertEqual(alerts, ["SQL Injection", "XSS"])

    def test_parse_zap_report_invalid_json_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            WebappExecutor._parse_zap_report("not json")

    def test_parse_sqlmap(self):
        stdout = (
            "Parameter: id (GET)\n    Type: boolean-based blind\nParameter: id (GET)"
        )
        vulns = WebappExecutor._parse_sqlmap(stdout)
        self.assertEqual(vulns, ["Parameter: id (GET)"])


class RedactUrlTest(TestCase):
    def test_redacts_credentials_and_query(self):
        redacted = WebappExecutor._redact_url(
            "http://user:pass@example.com/app?token=secret"
        )
        self.assertNotIn("user", redacted)
        self.assertNotIn("pass", redacted)
        self.assertNotIn("secret", redacted)
        self.assertIn("***@example.com", redacted)
        self.assertIn("<redacted>", redacted)

    def test_leaves_plain_url_and_flags_untouched(self):
        self.assertEqual(
            WebappExecutor._redact_url("http://example.com/app"),
            "http://example.com/app",
        )
        self.assertEqual(WebappExecutor._redact_url("--batch"), "--batch")
