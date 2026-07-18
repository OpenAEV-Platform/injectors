"""Thin client over the Censys Search API v2 (hosts and certificates)."""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

import requests


@dataclass
class CensysResult:
    success: bool
    message: str
    outputs: Dict[str, List[Union[str, int]]] = field(default_factory=dict)


def _is_ipv4(value: Optional[str]) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


class CensysClient:
    def __init__(
        self,
        api_id: str,
        api_secret: str,
        base_url: str = "https://search.censys.io",
        per_page: int = 50,
        timeout: int = 60,
        max_pages: int = 10,
        logger=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.per_page = per_page
        self.timeout = timeout
        self.max_pages = max(1, max_pages)
        self.logger = logger
        self._auth = (api_id, api_secret)

    def _log_error(self, message: str) -> None:
        if self.logger:
            self.logger.error(message)

    def _get(self, path: str, params: Dict) -> Dict:
        response = requests.get(
            f"{self.base_url}{path}",
            params=params,
            auth=self._auth,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def _search_all_hits(self, path: str, query: str) -> List[Dict]:
        """Fetch and aggregate hits across pages using the Censys cursor.

        The Censys Search API v2 is cursor-paginated: each response exposes the
        next-page token at ``result.links.next`` (empty when the last page is
        reached). We follow it up to ``max_pages`` to bound API usage and avoid
        an unbounded loop if the API ever keeps returning a cursor.
        """
        hits: List[Dict] = []
        cursor: Optional[str] = None
        for _ in range(self.max_pages):
            params: Dict[str, Union[str, int]] = {
                "q": query,
                "per_page": self.per_page,
            }
            if cursor:
                params["cursor"] = cursor
            result = self._get(path, params).get("result", {})
            hits.extend(result.get("hits", []))
            cursor = (result.get("links") or {}).get("next")
            if not cursor:
                break
        return hits

    def search_hosts(self, query: str) -> CensysResult:
        try:
            hits = self._search_all_hits("/api/v2/hosts/search", query)
        except requests.HTTPError as exc:
            message = f"Censys host search failed: {exc}"
            self._log_error(message)
            return CensysResult(False, message)
        except requests.RequestException as exc:
            message = f"Censys request error: {exc}"
            self._log_error(message)
            return CensysResult(False, message)

        hosts = [h.get("ip") for h in hits if _is_ipv4(h.get("ip"))]
        ports = sorted(
            {
                int(svc.get("port"))
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
            hits = self._search_all_hits("/api/v2/certificates/search", query)
        except requests.HTTPError as exc:
            message = f"Censys certificate search failed: {exc}"
            self._log_error(message)
            return CensysResult(False, message)
        except requests.RequestException as exc:
            message = f"Censys request error: {exc}"
            self._log_error(message)
            return CensysResult(False, message)

        fingerprints = [
            h.get("fingerprint_sha256") for h in hits if h.get("fingerprint_sha256")
        ]
        return CensysResult(
            success=True,
            message=f"Found {len(fingerprints)} certificates",
            outputs={"certificates": fingerprints},
        )
