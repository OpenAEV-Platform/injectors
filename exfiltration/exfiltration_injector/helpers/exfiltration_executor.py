"""Performs simulated data-exfiltration egress from the injector container.

The payload is random bytes (no real sensitive data), so this exercises egress
filtering and DLP without leaking anything. Whether the egress succeeds or is
blocked is what the DETECTION / PREVENTION expectations measure - so a blocked
attempt is still a completed inject, not an injector error.
"""

import base64
import os
import socket
from dataclasses import dataclass, field
from typing import Dict, List

import requests

# DNS labels are capped at 63 characters; leave room for the index label.
_MAX_LABEL = 60


def random_payload(size_kb: int) -> bytes:
    return os.urandom(max(size_kb, 1) * 1024)


@dataclass
class ExfilResult:
    success: bool
    message: str
    outputs: Dict[str, List[str]] = field(default_factory=dict)


class ExfiltrationExecutor:
    def __init__(self, logger=None, timeout: int = 60):
        self.logger = logger
        self.timeout = timeout

    @staticmethod
    def _chunk(encoded: str) -> List[str]:
        return [encoded[i : i + _MAX_LABEL] for i in range(0, len(encoded), _MAX_LABEL)]

    def exfiltrate_dns(self, domain: str, size_kb: int) -> ExfilResult:
        encoded = base64.b32encode(random_payload(size_kb)).decode().lower().rstrip("=")
        chunks = self._chunk(encoded)
        queries = 0
        for index, chunk in enumerate(chunks):
            host = f"{chunk}.{index}.{domain}"
            try:
                socket.getaddrinfo(host, None)
            except (OSError, UnicodeError):
                # Expected: the crafted host usually will not resolve. We only
                # care that the DNS query left the network.
                pass
            queries += 1
        return ExfilResult(
            success=True,
            message=(
                f"Issued {queries} DNS queries encoding {len(encoded)} bytes to "
                f"{domain}"
            ),
            outputs={"dns_queries": [str(queries)], "domain": [domain]},
        )

    def exfiltrate_https(self, url: str, size_kb: int) -> ExfilResult:
        payload = random_payload(size_kb)
        try:
            response = requests.post(
                url,
                data=payload,
                headers={"Content-Type": "application/octet-stream"},
                timeout=self.timeout,
            )
            return ExfilResult(
                success=True,
                message=(
                    f"Exfiltrated {len(payload)} bytes over HTTPS to {url} "
                    f"(HTTP {response.status_code})"
                ),
                outputs={"bytes": [str(len(payload))], "url": [url]},
            )
        except requests.RequestException as exc:
            return ExfilResult(
                success=True,
                message=f"HTTPS egress to {url} blocked or unreachable: {exc}",
                outputs={"bytes": ["0"], "url": [url]},
            )

    def exfiltrate_cloud(self, upload_url: str, size_kb: int) -> ExfilResult:
        payload = random_payload(size_kb)
        try:
            response = requests.put(upload_url, data=payload, timeout=self.timeout)
            return ExfilResult(
                success=True,
                message=(
                    f"Uploaded {len(payload)} bytes to cloud storage "
                    f"(HTTP {response.status_code})"
                ),
                outputs={"bytes": [str(len(payload))]},
            )
        except requests.RequestException as exc:
            return ExfilResult(
                success=True,
                message=f"Cloud upload blocked or unreachable: {exc}",
                outputs={"bytes": ["0"]},
            )
