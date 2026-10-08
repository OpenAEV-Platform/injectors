import os
import unittest
from unittest import mock

from nuclei.helpers.template_url import (
    TemplateUrlError,
    _AllowlistRedirectHandler,
    materialize_template_url,
)

ALLOWED = ["raw.githubusercontent.com"]


def _fake_response(data: bytes):
    resp = mock.MagicMock()
    resp.read.return_value = data
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


class MaterializeTemplateUrlTest(unittest.TestCase):
    def test_rejects_non_http_scheme(self):
        with self.assertRaises(TemplateUrlError):
            materialize_template_url("file:///etc/passwd", ALLOWED, 1000)

    def test_rejects_domain_not_in_allowlist(self):
        with self.assertRaises(TemplateUrlError):
            materialize_template_url("https://evil.example.com/t.yaml", ALLOWED, 1000)

    def test_rejects_oversize_download(self):
        with mock.patch(
            "urllib.request.OpenerDirector.open",
            return_value=_fake_response(b"x" * 2000),
        ):
            with self.assertRaises(TemplateUrlError):
                materialize_template_url(
                    "https://raw.githubusercontent.com/o/r/b/t.yaml", ALLOWED, 1000
                )

    def test_rejects_empty_content(self):
        with mock.patch(
            "urllib.request.OpenerDirector.open",
            return_value=_fake_response(b"   \n"),
        ):
            with self.assertRaises(TemplateUrlError):
                materialize_template_url(
                    "https://raw.githubusercontent.com/o/r/b/t.yaml", ALLOWED, 1000
                )

    def test_writes_allowed_template_to_temp_file(self):
        content = b"id: CVE-2026-76504\ninfo:\n  name: test\n"
        with mock.patch(
            "urllib.request.OpenerDirector.open",
            return_value=_fake_response(content),
        ):
            path = materialize_template_url(
                "https://raw.githubusercontent.com/o/r/b/http/cves/2026/CVE-2026-76504.yaml",
                ALLOWED,
                1_000_000,
            )
        try:
            self.assertTrue(os.path.exists(path))
            self.assertTrue(path.endswith(".yaml"))
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), content)
        finally:
            os.remove(path)


class AllowlistRedirectHandlerTest(unittest.TestCase):
    """A redirect to a non-allowlisted host must be refused (SSRF guard)."""

    def test_redirect_to_disallowed_host_is_refused(self):
        handler = _AllowlistRedirectHandler(ALLOWED)
        with self.assertRaises(TemplateUrlError):
            handler.redirect_request(
                mock.MagicMock(),
                mock.MagicMock(),
                302,
                "Found",
                {},
                "http://169.254.169.254/latest/meta-data/",
            )

    def test_redirect_to_allowed_host_is_permitted(self):
        handler = _AllowlistRedirectHandler(ALLOWED)
        # does not raise; delegates to the base handler to build the next Request
        with mock.patch.object(
            _AllowlistRedirectHandler.__bases__[0],
            "redirect_request",
            return_value="ok",
        ):
            result = handler.redirect_request(
                mock.MagicMock(),
                mock.MagicMock(),
                302,
                "Found",
                {},
                "https://raw.githubusercontent.com/o/r/b/t.yaml",
            )
        self.assertEqual(result, "ok")


if __name__ == "__main__":
    unittest.main()
