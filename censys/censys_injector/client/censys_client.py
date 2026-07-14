"""Thin client over the Censys Search API v2 (hosts and certificates)."""

from dataclasses import dataclass, field
from typing import Dict, List

import requests


@dataclass
class CensysResult:
    success: bool
    message: str
    outputs: Dict[str, List[str]] = field(default_factory=dict)


class CensysClient:
    def __init__(
        self,
        api_id: str,
        api_secret: str,
        base_url: str = "https://search.censys.io",
        per_page: int = 50,
        timeout: int = 60,
        logger=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.per_page = per_page
        self.timeout = timeout
        self.logger = logger
        self._auth = (api_id, api_secret)

    def _get(self, path: str, params: Dict) -> Dict:
        response = requests.get(
            f"{self.base_url}{path}",
            params=params,
            auth=self._auth,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def search_hosts(self, query: str) -> CensysResult:
        try:
            payload = self._get(
                "/api/v2/hosts/search",
                {"q": query, "per_page": self.per_page},
            )
        except requests.HTTPError as exc:
            return CensysResult(False, f"Censys host search failed: {exc}")
        except requests.RequestException as exc:
            return CensysResult(False, f"Censys request error: {exc}")

        hits = payload.get("result", {}).get("hits", [])
        hosts = [h.get("ip") for h in hits if h.get("ip")]
        ports = sorted(
            {
                str(svc.get("port"))
                for h in hits
                for svc in h.get("services", [])
                if svc.get("port")
            }
        )
        return CensysResult(
            success=True,
            message=f"Found {len(hosts)} hosts, {len(ports)} distinct ports",
            outputs={"hosts": hosts, "ports": ports},
        )

    def search_certificates(self, query: str) -> CensysResult:
        try:
            payload = self._get(
                "/api/v2/certificates/search",
                {"q": query, "per_page": self.per_page},
            )
        except requests.HTTPError as exc:
            return CensysResult(False, f"Censys certificate search failed: {exc}")
        except requests.RequestException as exc:
            return CensysResult(False, f"Censys request error: {exc}")

        hits = payload.get("result", {}).get("hits", [])
        fingerprints = [
            h.get("fingerprint_sha256") for h in hits if h.get("fingerprint_sha256")
        ]
        return CensysResult(
            success=True,
            message=f"Found {len(fingerprints)} certificates",
            outputs={"certificates": fingerprints},
        )
