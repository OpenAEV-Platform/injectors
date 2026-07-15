import urllib.error
import urllib.request
from unittest import TestCase

from phishing_injector.contracts_phishing import (
    PHISHING_CAMPAIGN_CONTRACT,
    PhishingContracts,
)
from phishing_injector.helpers import templates
from phishing_injector.openaev_phishing import OpenAEVPhishing
from phishing_injector.tracking.server import (
    REQUEST_TIMEOUT_SECONDS,
    TrackingServer,
    build_handler,
)
from phishing_injector.tracking.store import CampaignStore


class ContractsTest(TestCase):
    def test_build_contract(self):
        contracts = PhishingContracts.build_contract()
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["contract_id"], PHISHING_CAMPAIGN_CONTRACT)


class TemplateTest(TestCase):
    def test_render_embeds_tracking_urls(self):
        rendered = templates.render("password_reset", "http://host:8080", "tok123")
        self.assertIn("http://host:8080/c/tok123", rendered["html"])
        self.assertIn("http://host:8080/o/tok123", rendered["html"])
        self.assertTrue(rendered["subject"])

    def test_custom_html_placeholders(self):
        rendered = templates.render(
            "password_reset",
            "http://host:8080",
            "tok123",
            custom_html='<a href="{link}">x</a><img src="{pixel}">',
        )
        self.assertIn("http://host:8080/c/tok123", rendered["html"])

    def test_unknown_template_raises(self):
        with self.assertRaises(ValueError):
            templates.render("nope", "http://host", "tok")


class RecipientParsingTest(TestCase):
    def test_parse_mixed_separators(self):
        raw = "a@x.com, b@x.com\nc@x.com;d@x.com"
        self.assertEqual(
            OpenAEVPhishing.parse_recipients(raw),
            ["a@x.com", "b@x.com", "c@x.com", "d@x.com"],
        )

    def test_parse_empty(self):
        self.assertEqual(OpenAEVPhishing.parse_recipients(""), [])


class TrackingServerTest(TestCase):
    def setUp(self):
        self.store = CampaignStore()
        self.store.register("tok", "inject-1", "victim@example.com")
        self.server = TrackingServer(self.store, host="127.0.0.1", port=0)
        self.server.start()
        self.base = f"http://127.0.0.1:{self.server.port}"

    def tearDown(self):
        self.server.stop()

    def test_open_pixel_records_open(self):
        with urllib.request.urlopen(f"{self.base}/o/tok") as resp:
            self.assertEqual(resp.status, 200)
        self.assertEqual(self.store.stats("inject-1").opened, 1)

    def test_click_records_click(self):
        with urllib.request.urlopen(f"{self.base}/c/tok") as resp:
            self.assertEqual(resp.status, 200)
        stats = self.store.stats("inject-1")
        self.assertEqual(stats.clicked, 1)
        self.assertEqual(stats.opened, 1)

    def test_submit_records_submit(self):
        request = urllib.request.Request(
            f"{self.base}/s/tok", data=b"username=a&password=b", method="POST"
        )
        # The submit endpoint replies with a 302 redirect to an external site;
        # block following it and just confirm the event was recorded.
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            opener.open(request)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 302)
        self.assertEqual(self.store.stats("inject-1").submitted, 1)


class TrackingServerLifecycleTest(TestCase):
    def test_stop_before_start_does_not_deadlock(self):
        server = TrackingServer(CampaignStore(), host="127.0.0.1", port=0)
        # stop() must be safe when serve_forever() was never started: calling
        # shutdown() first would block forever, so it must be guarded.
        server.stop()

    def test_handler_has_request_timeout(self):
        # A per-request socket timeout must be set so a slow/stalled client
        # cannot pin a handler thread indefinitely (slowloris) despite the
        # Content-Length cap.
        handler = build_handler(CampaignStore(), "<html></html>", "http://x/")
        self.assertEqual(handler.timeout, REQUEST_TIMEOUT_SECONDS)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
