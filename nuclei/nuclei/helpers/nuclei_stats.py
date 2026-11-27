"""Scan coverage out of Nuclei's JSON progress statistics.

With ``-stats -stats-json -stats-interval N`` Nuclei writes one JSON object per line
on stderr every N seconds, and a final one when it exits normally (progress.go,
printCallbackJSON / metricsMap). Each object carries, as strings: ``hosts``,
``templates``, ``requests`` (sent so far), ``total`` (requests planned),
``percent``, ``matched``, ``errors``, ``rps``, ``duration`` (h:mm:ss) and
``startedAt``. The last line read before a kill is the coverage at cut-off.
"""

import json
from typing import Dict, Optional, Union

# Keys a Nuclei statistics line always carries (a finding line carries none).
_STATS_KEYS = ("requests", "total", "hosts", "templates")
COVERAGE_UNKNOWN = "coverage unknown (no Nuclei progress statistics captured)"


def _int(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def last_stats(stream: Union[bytes, str, None]) -> Optional[Dict]:
    """The coverage of the last statistics line of ``stream`` (Nuclei's stderr), or
    None when it holds none: {requests, total, percent, hosts, templates, matched,
    errors, duration}."""
    if not isinstance(stream, (bytes, str)) or not stream:
        return None
    if isinstance(stream, bytes):
        stream = stream.decode("utf-8", "replace")
    for line in reversed(stream.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or not all(k in data for k in _STATS_KEYS):
            continue
        requests = _int(data.get("requests"))
        total = _int(data.get("total"))
        if requests is None or total is None:
            continue
        percent = (requests * 100 // total) if total else None
        return {
            "requests": requests,
            "total": total,
            "percent": percent,
            "hosts": _int(data.get("hosts")),
            "templates": _int(data.get("templates")),
            "matched": _int(data.get("matched")),
            "errors": _int(data.get("errors")),
            "duration": data.get("duration") or None,
        }
    return None


def describe_coverage(coverage: Optional[Dict], prefix: str = "coverage") -> str:
    """E.g. 'coverage at cut-off: 41% of requests (1,234,567 / 3,000,000), 193 hosts,
    3,100 templates, 0:59:58 elapsed', or COVERAGE_UNKNOWN."""
    if not coverage:
        return COVERAGE_UNKNOWN
    requests, total = coverage["requests"], coverage["total"]
    if coverage.get("percent") is not None:
        head = f"{coverage['percent']}% of requests ({requests:,} / {total:,})"
    else:
        head = f"{requests:,} requests sent (total unknown)"
    parts = [head]
    if coverage.get("hosts") is not None:
        parts.append(f"{coverage['hosts']:,} hosts")
    if coverage.get("templates") is not None:
        parts.append(f"{coverage['templates']:,} templates")
    if coverage.get("errors"):
        parts.append(f"{coverage['errors']:,} request errors")
    if coverage.get("duration"):
        parts.append(f"{coverage['duration']} elapsed")
    return f"{prefix}: " + ", ".join(parts)
