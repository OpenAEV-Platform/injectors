import json
import re
from collections import defaultdict
from typing import Dict


class NucleiOutputParser:
    def parse(self, stdout: str, ip_to_asset_id_map: dict) -> Dict:
        grouped = defaultdict(
            lambda: {"asset_id": set(), "host": set(), "severity": None}
        )
        others = []
        seen = set()

        for line in stdout.splitlines():
            try:
                j = json.loads(line)
                if j.get("matcher-status"):
                    cve_ids = (
                        j.get("info", {})
                        .get("classification", {})
                        .get("cve-id", ["Unknown CVE"])
                    )
                    severity = j.get("info", {}).get("severity", "Unknown Severity")
                    host = j.get("host", j.get("url", ""))
                    cve_str = (
                        ", ".join(c.upper() for c in cve_ids)
                        if isinstance(cve_ids, list)
                        else cve_ids.upper()
                    )
                    key = (host, cve_str, severity)
                    if key not in seen:
                        seen.add(key)
                        asset_id = ip_to_asset_id_map.get(host, "")
                        # Group by each individual CVE inside the joined string
                        for cve_id in cve_str.split(", "):
                            group = grouped[cve_id]
                            group["asset_id"].add(asset_id)
                            group["host"].add(host)
                            group["severity"] = severity
            except json.JSONDecodeError:
                clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line)
                if clean_line.strip():
                    others.append(clean_line)

        grouped_findings = [
            {
                "id": cve_id,
                "asset_id": sorted(list(data["asset_id"])),
                "host": sorted(list(data["host"])),
                "severity": data["severity"],
            }
            for cve_id, data in grouped.items()
        ]

        message_parts = []
        if grouped_findings:
            message_parts.append(f"{len(grouped_findings)} CVE(S)")
        if others:
            message_parts.append(f"{len(others)} Vulnerabilities(s)")
        if not grouped_findings and not others:
            message_parts.append("Good News: Nothing Found !")

        return {
            "message": "Nuclei completed: " + " ".join(message_parts),
            "outputs": {"cve": grouped_findings, "others": others},
        }
