"""Coverage out of Nuclei's JSON progress statistics (OpenAEV-Platform/injectors#576)."""

import json

from nuclei.helpers.nuclei_stats import COVERAGE_UNKNOWN, describe_coverage, last_stats


def _stats(requests, total, **extra):
    # The shape nuclei v3 writes with -stats-json (progress.go, metricsMap).
    line = {
        "startedAt": "2026-11-27T07:00:00Z",
        "duration": "0:59:58",
        "templates": "3100",
        "hosts": "193",
        "matched": "0",
        "requests": str(requests),
        "total": str(total),
        "rps": "300",
        "errors": "12",
        "percent": str(requests * 100 // total),
    }
    line.update(extra)
    return json.dumps(line)


def test_last_stats_line_wins():
    stderr = "\n".join(
        [
            "[INF] Current nuclei version: v3.11.1",
            _stats(1000, 3_000_000),
            "[WRN] some warning",
            _stats(1_234_567, 3_000_000),
            "",
        ]
    ).encode()
    coverage = last_stats(stderr)
    assert coverage["requests"] == 1_234_567
    assert coverage["total"] == 3_000_000
    assert coverage["percent"] == 41
    assert coverage["hosts"] == 193
    assert coverage["templates"] == 3100
    assert coverage["duration"] == "0:59:58"


def test_no_stats_line():
    assert last_stats(b"[INF] nuclei started\n") is None
    assert last_stats(None) is None
    assert last_stats(b"") is None
    # A finding line (no stats keys) is not a stats line.
    assert last_stats(json.dumps({"host": "10.0.0.1"})) is None


def test_describe():
    text = describe_coverage(last_stats(_stats(1_234_567, 3_000_000)), "at cut-off")
    assert text == (
        "at cut-off: 41% of requests (1,234,567 / 3,000,000), 193 hosts, "
        "3,100 templates, 12 request errors, 0:59:58 elapsed"
    )
    assert describe_coverage(None) == COVERAGE_UNKNOWN


def test_zero_total():
    coverage = last_stats(_stats(0, 1).replace('"total": "1"', '"total": "0"'))
    assert coverage["total"] == 0
    assert coverage["percent"] is None
    assert describe_coverage(coverage).startswith("coverage: 0 requests sent")
