import os
from unittest import mock

import pytest

from nuclei.helpers.template_url import TemplateUrlError, materialize_template_url

ALLOWED = ["raw.githubusercontent.com"]


def _fake_response(data: bytes):
    resp = mock.MagicMock()
    resp.read.return_value = data
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_rejects_non_http_scheme():
    with pytest.raises(TemplateUrlError):
        materialize_template_url("file:///etc/passwd", ALLOWED, 1000)


def test_rejects_domain_not_in_allowlist():
    with pytest.raises(TemplateUrlError):
        materialize_template_url("https://evil.example.com/t.yaml", ALLOWED, 1000)


def test_rejects_oversize_download():
    big = b"x" * 2000
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(big)):
        with pytest.raises(TemplateUrlError):
            materialize_template_url(
                "https://raw.githubusercontent.com/o/r/b/t.yaml", ALLOWED, 1000
            )


def test_rejects_empty_content():
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(b"   \n")):
        with pytest.raises(TemplateUrlError):
            materialize_template_url(
                "https://raw.githubusercontent.com/o/r/b/t.yaml", ALLOWED, 1000
            )


def test_writes_allowed_template_to_temp_file():
    content = b"id: CVE-2026-76504\ninfo:\n  name: test\n"
    with mock.patch("urllib.request.urlopen", return_value=_fake_response(content)):
        path = materialize_template_url(
            "https://raw.githubusercontent.com/o/r/b/http/cves/2026/CVE-2026-76504.yaml",
            ALLOWED,
            1_000_000,
        )
    try:
        assert os.path.exists(path)
        assert path.endswith(".yaml")
        with open(path, "rb") as handle:
            assert handle.read() == content
    finally:
        os.remove(path)
