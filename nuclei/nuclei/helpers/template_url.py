"""Fetch a Nuclei template from an allowlisted URL to a local temp file.

The deployed Nuclei binary does not load remote templates itself (the -tu /
-remote-template-domain flags are rejected), but it runs a local template path
fine. So when an inject provides a `template_url`, the injector downloads the
template to a temporary file and passes it to Nuclei as `-templates <path>`.
This lets an operator run a template that is not yet merged into the local
template store (e.g. one still in review in a pull request), with Nuclei's full
matching logic, while keeping the fetch under an explicit domain allowlist and
size cap.
"""

import os
import tempfile
import urllib.error
import urllib.request
from urllib.parse import urlparse


class TemplateUrlError(Exception):
    """Raised when a template_url is rejected or cannot be fetched."""


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
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TemplateUrlError(
            f"template_url must use http(s), got '{parsed.scheme or '<none>'}'"
        )
    host = (parsed.hostname or "").lower()
    allowed = [d.lower() for d in (allowed_domains or [])]
    if host not in allowed:
        raise TemplateUrlError(
            f"template_url domain '{host}' is not allowed "
            f"(allowed: {', '.join(allowed) or '<none>'})"
        )

    request = urllib.request.Request(
        url, headers={"User-Agent": "openaev-nuclei-injector"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # read one byte past the cap so an over-size file is detected
            data = response.read(max_bytes + 1)
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
