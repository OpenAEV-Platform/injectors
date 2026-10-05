"""Parse Shodan search results into finding-compatible structured outputs.

Turns the raw Shodan matches (already retrieved for every contract) into the
``IPv4``, ``PortsScan`` and ``CVE`` finding shapes declared in
``shodan.contracts.finding_outputs``. The output-dict keys MUST match the
declared ``ContractOutputElement`` fields and the platform OutputProcessor
contracts.

Only findings that satisfy the platform validators are emitted:

- IPv4      -> a valid IPv4 address string
- PortsScan -> host + numeric port + service
- CVE       -> id + host + severity

``asset_id`` is attached only when a match maps back to a resolved target asset,
mirroring the netexec / ai-redteam convention of never emitting a null asset id.
"""

import ipaddress

from shodan.contracts.finding_outputs import CVE_FIELD, IPV4_FIELD, PORTS_SCAN_FIELD


class ShodanFindingsParser:
    """Extract IPv4 / PortsScan / CVE findings from Shodan search results."""

    @staticmethod
    def _is_ipv4(value) -> bool:
        try:
            return isinstance(value, str) and ipaddress.ip_address(value).version == 4
        except ValueError:
            return False

    @staticmethod
    def _build_asset_map(targets: dict) -> dict:
        """Map every known target IP / seen IP / hostname to its asset id."""
        asset_map: dict = {}
        for asset in targets.get("assets", []) or []:
            asset_id = asset.get("asset_id")
            if not asset_id:
                continue
            for ip in asset.get("asset_ips") or []:
                if ip:
                    asset_map.setdefault(ip, asset_id)
            seen_ip = asset.get("asset_seen_ip")
            if seen_ip:
                asset_map.setdefault(seen_ip, asset_id)
            hostname = asset.get("asset_hostname")
            if hostname:
                asset_map.setdefault(hostname, asset_id)
        return asset_map

    @staticmethod
    def _iter_elements(shodan_results: dict):
        """Yield every Shodan match across all target responses."""
        for item in shodan_results.get("data", []) or []:
            if not isinstance(item, dict) or item.get("is_error"):
                continue
            result = item.get("result") or {}
            if not isinstance(result, dict):
                continue
            elements = result.get("matches")
            if elements is None:
                # CVE_SPECIFIC_WATCHLIST responses expose matches under "data".
                elements = result.get("data", [])
            for element in elements or []:
                if isinstance(element, dict):
                    yield element

    @staticmethod
    def _resolve_asset_id(element: dict, ip_str, asset_map: dict):
        if ip_str and ip_str in asset_map:
            return asset_map[ip_str]
        for hostname in element.get("hostnames", []) or []:
            if hostname in asset_map:
                return asset_map[hostname]
        return None

    @staticmethod
    def _iter_cves(vulns):
        """Yield (cve_id, severity) pairs from a Shodan ``vulns`` field.

        Shodan exposes ``vulns`` either as a mapping ``{CVE-ID: {cvss: float}}``
        or, more rarely, as a plain list of CVE identifiers.
        """
        if isinstance(vulns, dict):
            for cve_id, meta in vulns.items():
                severity = "Unknown"
                if isinstance(meta, dict) and meta.get("cvss") is not None:
                    severity = str(meta.get("cvss"))
                yield str(cve_id).upper(), severity
        elif isinstance(vulns, list):
            for cve_id in vulns:
                if isinstance(cve_id, str):
                    yield cve_id.upper(), "Unknown"

    def parse(self, normalize_input_data, shodan_results: dict) -> dict:
        """Return the IPv4 / PortsScan / CVE findings for a Shodan execution."""
        targets = normalize_input_data.targets.model_dump()
        asset_map = self._build_asset_map(targets)

        ipv4_seen: set = set()
        ipv4_findings: list = []
        ports_scan_seen: set = set()
        ports_scan_findings: list = []
        cve_seen: set = set()
        cve_findings: list = []

        for element in self._iter_elements(shodan_results):
            ip_str = element.get("ip_str")
            asset_id = self._resolve_asset_id(element, ip_str, asset_map)
            host = ip_str or ""

            if self._is_ipv4(ip_str) and ip_str not in ipv4_seen:
                ipv4_seen.add(ip_str)
                ipv4_findings.append(ip_str)

            port = element.get("port")
            if host and isinstance(port, int) and not isinstance(port, bool):
                key = (host, port)
                if key not in ports_scan_seen:
                    ports_scan_seen.add(key)
                    finding = {
                        "host": host,
                        "port": port,
                        "service": (
                            element.get("product")
                            or element.get("transport")
                            or "unknown"
                        ),
                    }
                    if asset_id:
                        finding["asset_id"] = asset_id
                    ports_scan_findings.append(finding)

            for cve_id, severity in self._iter_cves(element.get("vulns")):
                if not host:
                    continue
                key = (cve_id, host)
                if key in cve_seen:
                    continue
                cve_seen.add(key)
                finding = {"id": cve_id, "host": host, "severity": severity}
                if asset_id:
                    finding["asset_id"] = asset_id
                cve_findings.append(finding)

        return {
            IPV4_FIELD: ipv4_findings,
            PORTS_SCAN_FIELD: ports_scan_findings,
            CVE_FIELD: cve_findings,
        }
