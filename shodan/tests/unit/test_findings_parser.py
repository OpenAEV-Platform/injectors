"""Unit tests for ShodanFindingsParser (IPv4 / PortsScan / CVE extraction)."""

from unittest.mock import MagicMock

from shodan.services.findings_parser import ShodanFindingsParser


def _normalize_input_data(assets):
    """Build a stand-in NormalizeInputData exposing targets.model_dump()."""
    nid = MagicMock()
    nid.targets.model_dump.return_value = {"assets": assets}
    return nid


def _results(matches):
    return {
        "targets": ["target"],
        "data": [
            {
                "target": "target",
                "url": "GET https://api.shodan.io/...",
                "result": {"matches": matches, "total": len(matches)},
            }
        ],
    }


def test_parse_extracts_ipv4_portscan_and_cve_with_asset_mapping():
    assets = [
        {
            "asset_id": "asset-1",
            "asset_hostname": None,
            "asset_ips": ["51.38.220.153"],
            "asset_seen_ip": None,
        }
    ]
    matches = [
        {
            "ip_str": "51.38.220.153",
            "hostnames": ["automation.filigran.io"],
            "port": 443,
            "product": "nginx",
            "vulns": {
                "CVE-2023-44487": {"cvss": 7.5},
                "cve-2025-23419": {"cvss": 4.3},
            },
        }
    ]

    outputs = ShodanFindingsParser().parse(
        _normalize_input_data(assets), _results(matches)
    )

    assert outputs["ipv4"] == ["51.38.220.153"]
    assert outputs["ports_scan"] == [
        {
            "host": "51.38.220.153",
            "port": 443,
            "service": "nginx",
            "asset_id": "asset-1",
        }
    ]
    assert {(c["id"], c["severity"]) for c in outputs["cve"]} == {
        ("CVE-2023-44487", "7.5"),
        ("CVE-2025-23419", "4.3"),
    }
    for cve in outputs["cve"]:
        assert cve["host"] == "51.38.220.153"
        assert cve["asset_id"] == "asset-1"


def test_parse_manual_mode_omits_asset_id_and_falls_back_on_service():
    matches = [
        {
            "ip_str": "1.1.1.1",
            "hostnames": [],
            "port": 22,
            "transport": "tcp",
        },
        {
            "ip_str": "8.8.8.8",
            "hostnames": [],
            "port": 53,
        },
    ]

    outputs = ShodanFindingsParser().parse(_normalize_input_data([]), _results(matches))

    assert outputs["ipv4"] == ["1.1.1.1", "8.8.8.8"]
    assert outputs["ports_scan"] == [
        {"host": "1.1.1.1", "port": 22, "service": "tcp"},
        {"host": "8.8.8.8", "port": 53, "service": "unknown"},
    ]
    assert outputs["cve"] == []


def test_parse_vulns_as_list_yields_unknown_severity():
    matches = [
        {
            "ip_str": "9.9.9.9",
            "hostnames": [],
            "vulns": ["CVE-2021-1234"],
        }
    ]

    outputs = ShodanFindingsParser().parse(_normalize_input_data([]), _results(matches))

    assert outputs["cve"] == [
        {"id": "CVE-2021-1234", "host": "9.9.9.9", "severity": "Unknown"}
    ]


def test_parse_deduplicates_and_skips_errors_and_non_ipv4():
    results = {
        "targets": ["a", "b"],
        "data": [
            {"target": "a", "is_error": True, "response": {}},
            {
                "target": "b",
                "result": {
                    "matches": [
                        {"ip_str": "1.2.3.4", "hostnames": [], "port": 80},
                        {"ip_str": "1.2.3.4", "hostnames": [], "port": 80},
                        {
                            "ip_str": "2001:db8::1",
                            "hostnames": [],
                            "port": 8080,
                        },
                    ]
                },
            },
        ],
    }

    outputs = ShodanFindingsParser().parse(_normalize_input_data([]), results)

    # IPv4 list only holds the valid, de-duplicated IPv4 address.
    assert outputs["ipv4"] == ["1.2.3.4"]
    # PortsScan keeps one entry per (host, port); the IPv6 host is still a
    # valid PortsScan host even though it is excluded from the IPv4 list.
    assert outputs["ports_scan"] == [
        {"host": "1.2.3.4", "port": 80, "service": "unknown"},
        {"host": "2001:db8::1", "port": 8080, "service": "unknown"},
    ]
