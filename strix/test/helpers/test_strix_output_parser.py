import json

from strix.helpers.strix_output_parser import StrixOutputParser


def _write_run(tmp_path, vulns=None, report=None):
    run = tmp_path / "run-abc"
    run.mkdir()
    if vulns is not None:
        (run / "vulnerabilities.json").write_text(
            json.dumps(vulns), encoding="utf-8"
        )
    if report is not None:
        (run / "penetration_test_report.md").write_text(report, encoding="utf-8")
    return run


def test_none_run_dir():
    out = StrixOutputParser().parse(None, {})
    assert out["outputs"]["cve"] == []
    assert "no run directory" in out["message"]


def test_empty_run(tmp_path):
    run = _write_run(tmp_path, vulns=[])
    out = StrixOutputParser().parse(run, {})
    assert out["outputs"]["cve"] == []
    assert out["outputs"]["others"] == []
    assert "No vulnerabilities reported" in out["message"]


def test_cve_grouping_and_asset_mapping(tmp_path):
    vulns = [
        {
            "id": "f1",
            "title": "Old Struts",
            "severity": "critical",
            "target": "https://app.example.com/",
            "cve": ["CVE-2017-5638"],
        },
        {
            "id": "f2",
            "title": "Same CVE other host",
            "severity": "high",
            "target": "http://10.0.0.2",
            "cve": "cve-2017-5638",
        },
    ]
    run = _write_run(tmp_path, vulns=vulns)
    mapping = {"app.example.com": "asset-1", "10.0.0.2": "asset-2"}
    out = StrixOutputParser().parse(run, mapping)
    cves = out["outputs"]["cve"]
    assert len(cves) == 1
    entry = cves[0]
    assert entry["id"] == "CVE-2017-5638"
    assert entry["asset_id"] == ["asset-1", "asset-2"]
    assert set(entry["host"]) == {"app.example.com", "10.0.0.2"}


def test_non_cve_findings_go_to_vulnerability(tmp_path):
    vulns = [
        {"id": "x", "title": "Reflected XSS", "severity": "medium",
         "target": "https://app.example.com/search"},
        {"id": "y", "title": "IDOR", "severity": "high", "endpoint": "/api/users/1"},
    ]
    run = _write_run(tmp_path, vulns=vulns)
    out = StrixOutputParser().parse(run, {})
    vulns_out = out["outputs"]["vulnerability"]
    by_name = {v["name"]: v for v in vulns_out}
    # Every vulnerability finding MUST carry name + status (OpenAEV requires both).
    assert all(v.get("name") and v.get("status") for v in vulns_out)
    assert by_name["Reflected XSS"]["status"] == "MEDIUM"
    assert by_name["Reflected XSS"]["host"] == "app.example.com"
    assert by_name["IDOR"]["status"] == "HIGH"
    assert out["outputs"]["cve"] == []
    assert out["outputs"]["others"] == []


def test_executive_report_becomes_action_output(tmp_path):
    run = _write_run(tmp_path, vulns=[], report="# Report\nAll good")
    out = StrixOutputParser().parse(run, {})
    assert out["outputs"]["action_output"].startswith("# Report")


def test_malformed_vulnerabilities_json_is_tolerated(tmp_path):
    run = tmp_path / "run-bad"
    run.mkdir()
    (run / "vulnerabilities.json").write_text("{not json", encoding="utf-8")
    out = StrixOutputParser().parse(run, {})
    assert out["outputs"]["cve"] == []
    assert out["outputs"]["others"] == []
