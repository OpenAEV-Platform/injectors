"""Turn a Strix run directory into OpenAEV structured outputs.

Strix writes, per run:
  * ``vulnerabilities.json`` - a list of finding dicts (id, title, severity,
    target, endpoint, method, cve, cwe, description, ...);
  * ``penetration_test_report.md`` - the executive report;
  * ``coverage.json`` - what was tested.

Mapping to OpenAEV finding-compatible outputs:
  * CVE-bearing findings -> ``cve`` (grouped like Nuclei);
  * every other finding  -> ``vulnerability`` (OpenAEV Vulnerability finding,
    shape {name, status, details, host, asset_id}) so web / logic bugs that
    carry no CVE (SQLi, XSS, broken auth, ...) still surface as real
    Vulnerabilities instead of plain text;
  * the executive report -> ``action_output`` (never a visible Finding, but
    usable as a chaining / event filter, same pattern as the Nuclei injector).
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

_MAX_ACTION_OUTPUT = 200_000
_MAX_DETAILS = 4_000


def _host_of(value: str) -> str:
    if not value:
        return ""
    # A bare path / fragment (e.g. "/#/search") has no host: don't let it leak in.
    if "://" not in value and value.lstrip().startswith(("/", "#", "?")):
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname
    if host:
        return host
    # No resolvable host and the value looks like a path -> empty.
    return "" if "/" in value else value


def _as_cve_list(report: dict) -> List[str]:
    cve = report.get("cve")
    if not cve:
        return []
    if isinstance(cve, list):
        return [str(c).upper() for c in cve if c]
    return [str(cve).upper()]


def _target_of(report: dict) -> str:
    return str(
        report.get("target") or report.get("endpoint") or report.get("url") or ""
    )


def _details_of(report: dict) -> str:
    method = str(report.get("method") or "").strip()
    endpoint = str(
        report.get("endpoint") or report.get("url") or report.get("target") or ""
    ).strip()
    cwe = report.get("cwe")
    description = str(report.get("description") or report.get("detail") or "").strip()
    parts: List[str] = []
    location = " ".join(p for p in (method, endpoint) if p).strip()
    if location:
        parts.append(location)
    if cwe:
        if isinstance(cwe, list):
            cwe = ", ".join(str(c) for c in cwe if c)
        parts.append(f"CWE: {cwe}")
    if description:
        parts.append(description)
    return "\n".join(parts)[:_MAX_DETAILS]


class StrixOutputParser:
    def _read_vulnerabilities(self, run_dir: Path) -> List[dict]:
        path = run_dir / "vulnerabilities.json"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        return data if isinstance(data, list) else []

    def _read_report(self, run_dir: Path) -> str:
        path = run_dir / "penetration_test_report.md"
        if not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    def parse(
        self,
        run_dir: Optional[Path],
        ip_to_asset_id_map: Optional[dict] = None,
    ) -> Dict:
        ip_to_asset_id_map = ip_to_asset_id_map or {}

        if run_dir is None:
            return {
                "message": "Strix completed: no run directory produced",
                "outputs": {"cve": [], "vulnerability": [], "others": []},
            }

        reports = self._read_vulnerabilities(run_dir)

        grouped = defaultdict(
            lambda: {"asset_id": set(), "host": set(), "severity": None}
        )
        vulnerabilities: List[dict] = []

        for report in reports:
            if not isinstance(report, dict):
                continue
            severity = str(report.get("severity", "unknown")).lower()
            target = _target_of(report)
            host = _host_of(target)
            asset_id = ip_to_asset_id_map.get(host, "")
            cves = _as_cve_list(report)
            if cves:
                for cve_id in cves:
                    group = grouped[cve_id]
                    if asset_id:
                        group["asset_id"].add(asset_id)
                    if host:
                        group["host"].add(host)
                    group["severity"] = severity
            else:
                name = (
                    report.get("title") or report.get("name") or "Untitled finding"
                )
                # OpenAEV VulnerabilityOutputProcessor requires name + status.
                # toFindingValue renders "name [status]"; severity is the most
                # useful status label for a scanner finding.
                vuln = {
                    "name": str(name),
                    "status": (
                        severity.upper()
                        if severity and severity != "unknown"
                        else "DETECTED"
                    ),
                    "details": _details_of(report),
                    "host": host,
                }
                if asset_id:
                    vuln["asset_id"] = asset_id
                vulnerabilities.append(vuln)

        grouped_findings = [
            {
                "id": cve_id,
                "asset_id": sorted(data["asset_id"]),
                "host": sorted(data["host"]),
                "severity": data["severity"],
            }
            for cve_id, data in grouped.items()
        ]

        message_parts = []
        if grouped_findings:
            message_parts.append(f"{len(grouped_findings)} CVE(s)")
        if vulnerabilities:
            message_parts.append(f"{len(vulnerabilities)} vulnerability(ies)")
        if not grouped_findings and not vulnerabilities:
            message_parts.append("No vulnerabilities reported")

        outputs: Dict = {
            "cve": grouped_findings,
            "vulnerability": vulnerabilities,
            "others": [],
        }

        report_md = self._read_report(run_dir)
        if report_md:
            outputs["action_output"] = report_md[:_MAX_ACTION_OUTPUT]

        return {
            "message": "Strix completed: " + ", ".join(message_parts),
            "outputs": outputs,
        }
