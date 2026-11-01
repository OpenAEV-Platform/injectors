import json
import os
import tempfile
from unittest import TestCase

from netexec.helpers.spider_plus_parser import (
    extract_files_from_metadata,
    parse_spider_output_dir,
)

# Trimmed real spider_plus metadata: a top-level file on NETLOGON and a
# deeply-nested file on SYSVOL.
_SAMPLE = {
    "NETLOGON": {
        "script.ps1": {"size": "165 B"},
        "secret.ps1": {"size": "869 B"},
    },
    "SYSVOL": {
        "north.sevenkingdoms.local/scripts/secret.ps1": {"size": "869 B"},
    },
}


class SpiderPlusParserTest(TestCase):

    def setUp(self):
        self.ip = "74.234.220.121"
        self.ip_map = {self.ip: "asset-001"}

    def _by_name(self, findings, name):
        return [f for f in findings if f["file_name"] == name]

    def test_extract_basename_and_directory(self):
        findings = extract_files_from_metadata(_SAMPLE, self.ip, self.ip_map)
        nested = self._by_name(findings, "secret.ps1")
        sysvol = [f for f in nested if f["share"] == "SYSVOL"][0]
        self.assertEqual(sysvol["file_name"], "secret.ps1")
        self.assertEqual(sysvol["path"], "north.sevenkingdoms.local/scripts")
        self.assertEqual(sysvol["share"], "SYSVOL")
        self.assertEqual(sysvol["host"], self.ip)
        self.assertEqual(sysvol["asset_id"], "asset-001")

    def test_top_level_file_has_empty_path(self):
        findings = extract_files_from_metadata(_SAMPLE, self.ip, self.ip_map)
        netlogon = [f for f in findings if f["share"] == "NETLOGON"]
        self.assertEqual(
            {f["file_name"] for f in netlogon}, {"script.ps1", "secret.ps1"}
        )
        self.assertTrue(all(f["path"] == "" for f in netlogon))

    def test_share_hosted_files_keep_distinct_findings_per_share(self):
        # Same basename on two shares must stay two findings (share differs), so
        # the platform's full-path value never collapses them.
        findings = extract_files_from_metadata(_SAMPLE, self.ip, self.ip_map)
        secrets = self._by_name(findings, "secret.ps1")
        self.assertEqual({f["share"] for f in secrets}, {"NETLOGON", "SYSVOL"})

    def test_no_asset_id_when_unmapped(self):
        findings = extract_files_from_metadata(_SAMPLE, self.ip, {})
        self.assertTrue(all("asset_id" not in f for f in findings))

    def test_empty_or_malformed_metadata(self):
        self.assertEqual(extract_files_from_metadata({}, self.ip, self.ip_map), [])
        self.assertEqual(
            extract_files_from_metadata({"SHARE": "not-a-dict"}, self.ip, self.ip_map),
            [],
        )

    def test_parse_output_dir_reads_ip_named_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, f"{self.ip}.json"), "w", encoding="utf-8") as f:
                json.dump(_SAMPLE, f)
            # A non-JSON file must be ignored.
            with open(os.path.join(d, "readme.txt"), "w", encoding="utf-8") as f:
                f.write("ignore me")
            findings = parse_spider_output_dir(d, self.ip_map)
        self.assertTrue(findings)
        self.assertTrue(all(f["host"] == self.ip for f in findings))
        self.assertTrue(all(f["asset_id"] == "asset-001" for f in findings))

    def test_parse_missing_dir_returns_empty(self):
        self.assertEqual(parse_spider_output_dir("/no/such/dir", self.ip_map), [])

    def test_parse_malformed_json_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "10.0.0.1.json"), "w", encoding="utf-8") as f:
                f.write("{ not valid json")
            self.assertEqual(parse_spider_output_dir(d, self.ip_map), [])
