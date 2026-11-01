"""Fetch a Nuclei template from an allowlisted URL to a local temp file.

The deployed Nuclei binary does not load remote templates itself (the -tu /
-remote-template-domain flags are rejected), but it runs a local template path
fine. So when an inject provides a `template_url`, the injector downloads the
template to a temporary file and passes it to Nuclei as `-templates <path>`.
This lets an operator run a template that is not yet merged into the local
template store (e.g. one still in review in a pull request), with Nuclei's full
matching logic, while keeping the fetch under an explicit domain allowlist and
size cap.

SSRF hardening: the allowlist is enforced on the original URL AND re-checked on
every HTTP redirect hop, so an allowlisted endpoint cannot bounce the
server-side request to an internal or otherwise non-allowlisted host.
"""

import os
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse


class TemplateUrlError(Exception):
    """Raised when a template_url is rejected or cannot be fetched."""


def _host_allowed(url: str, allowed: list[str]) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme in ("http", "https")
        and (parsed.hostname or "").lower() in allowed
    )


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect target against the domain allowlist.

    The default handler already caps redirect depth and detects loops; this
    subclass additionally refuses any hop whose scheme/host is not allowlisted,
    closing the redirect-based SSRF bypass.
    """

    def __init__(self, allowed: list[str]):
        self._allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _host_allowed(newurl, self._allowed):
            raise TemplateUrlError(
                f"template_url redirect to a non-allowlisted location is refused: {newurl}"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def materialize_template_url(
    url: str,
    allowed_domains: list[str],
    max_bytes: int,
    timeout: int = 30,
) -> str:
    """Download ``url`` to a temporary ``.yaml`` file and return its path.

    The caller is responsible for deleting the returned file once the scan is
    done. Raises :class:`TemplateUrlError` on any validation or fetch failure so
    the inject fails with an actionable message instead of a bare Nuclei error.
    """
    allowed = [d.lower() for d in (allowed_domains or [])]
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TemplateUrlError(
            f"template_url must use http(s), got '{parsed.scheme or '<none>'}'"
        )
    if (parsed.hostname or "").lower() not in allowed:
        raise TemplateUrlError(
            f"template_url domain '{(parsed.hostname or '').lower()}' is not allowed "
            f"(allowed: {', '.join(allowed) or '<none>'})"
        )

    opener = urllib.request.build_opener(_AllowlistRedirectHandler(allowed))
    request = urllib.request.Request(
        url, headers={"User-Agent": "openaev-nuclei-injector"}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            # read one byte past the cap so an over-size file is detected
            data = response.read(max_bytes + 1)
    except TemplateUrlError:
        raise
    except (urllib.error.URLError, OSError) as exc:
        raise TemplateUrlError(f"could not fetch template_url: {exc}") from exc

    if len(data) > max_bytes:
        raise TemplateUrlError(
            f"template_url content exceeds the {max_bytes} byte limit"
        )
    if not data.strip():
        raise TemplateUrlError("template_url returned empty content")

    fd, path = tempfile.mkstemp(suffix=".yaml", prefix="oaev-nuclei-tpl-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError as exc:
        try:
            os.remove(path)
        except OSError:
            pass
        raise TemplateUrlError(f"could not write template to disk: {exc}") from exc
    return path
