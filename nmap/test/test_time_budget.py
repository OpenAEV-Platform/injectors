"""Safe defaults for empty timing fields and the whole-run scan time limit (#572)."""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

import nmap.openaev_nmap as module
from injector_common.outcomes import ERROR, NOT_SCANNED, WARNING
from injector_common.scan_budget import DEFAULT_SCAN_TIMEOUT, THRESHOLD_SETTING_KEY
from injector_common.targets import Targets
from nmap.configuration.nmap_configs import ConfigLoaderNmap
from nmap.contracts.nmap_constants import (
    HOST_TIMEOUT_KEY,
    MAX_RETRIES_KEY,
    TCP_SYN_SCAN_CONTRACT,
)
from nmap.helpers.nmap_command_builder import NmapCommandBuilder
from nmap.helpers.nmap_output_parser import TIME_LIMIT_REASON, NmapOutputParser

SAFE_DEFAULTS = {HOST_TIMEOUT_KEY: 300, MAX_RETRIES_KEY: 2}


def _flag(args, flag):
    return args[args.index(flag) + 1] if flag in args else None


class TestSafeDefaults(unittest.TestCase):
    def test_empty_fields_get_the_safe_defaults(self):
        for empty in ({}, {HOST_TIMEOUT_KEY: None, MAX_RETRIES_KEY: ""}, None):
            args = NmapCommandBuilder.build_args(
                TCP_SYN_SCAN_CONTRACT, ["10.0.0.1"], empty, defaults=SAFE_DEFAULTS
            )
            self.assertEqual(_flag(args, "--host-timeout"), "300s")
            self.assertEqual(_flag(args, "--max-retries"), "2")

    def test_explicit_values_win_zero_included(self):
        args = NmapCommandBuilder.build_args(
            TCP_SYN_SCAN_CONTRACT,
            ["10.0.0.1"],
            {HOST_TIMEOUT_KEY: "0", MAX_RETRIES_KEY: "5"},
            defaults=SAFE_DEFAULTS,
        )
        self.assertEqual(_flag(args, "--host-timeout"), "0s")
        self.assertEqual(_flag(args, "--max-retries"), "5")

    def test_timing_template_keeps_nmap_default(self):
        args = NmapCommandBuilder.build_args(
            TCP_SYN_SCAN_CONTRACT, ["10.0.0.1"], {}, defaults=SAFE_DEFAULTS
        )
        self.assertFalse(any(a in args for a in ("-T0", "-T3", "-T4", "-T5")))

    def test_a_zero_default_adds_nothing(self):
        args = NmapCommandBuilder.build_args(
            TCP_SYN_SCAN_CONTRACT,
            ["10.0.0.1"],
            {},
            defaults={HOST_TIMEOUT_KEY: 0, MAX_RETRIES_KEY: 0},
        )
        self.assertNotIn("--host-timeout", args)
        self.assertNotIn("--max-retries", args)

    def test_deployment_config_defaults_and_empty_env(self):
        config = ConfigLoaderNmap()
        self.assertEqual(config.default_host_timeout_seconds, 300)
        self.assertEqual(config.default_max_retries, 2)
        self.assertIsNone(config.scan_timeout)
        config = ConfigLoaderNmap(
            default_host_timeout_seconds="", default_max_retries="", scan_timeout=""
        )
        self.assertEqual(config.default_host_timeout_seconds, 300)
        self.assertEqual(config.default_max_retries, 2)
        self.assertIsNone(config.scan_timeout)
        config = ConfigLoaderNmap(
            default_host_timeout_seconds="120", default_max_retries="1"
        )
        self.assertEqual(config.default_host_timeout_seconds, 120)
        self.assertEqual(config.default_max_retries, 1)


_HOST_1 = (
    b'<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
    b'<hostnames/><ports><port protocol="tcp" portid="22">'
    b'<state state="open"/><service name="ssh"/></port></ports></host>'
)
_HEADER = b'<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap">'
# A run killed while nmap was working on the second host: its <host> is cut.
_KILLED = _HEADER + _HOST_1 + b'<host><status state="up"/><address addr="10.0'


def _three_targets():
    assets = [
        {"asset_id": f"a{i}", "asset_name": f"web-0{i}", "asset_seen_ip": ip}
        for i, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3"], start=1)
    ]
    data = {"injection": {"inject_content": {}}, "assets": assets}
    return Targets.extract_targets("asset-groups", "seen_ip", data, MagicMock())


class TestSalvagePartial(unittest.TestCase):
    def test_keeps_the_completed_hosts(self):
        report = NmapOutputParser.salvage_partial(_KILLED)
        self.assertEqual(report, _HEADER + _HOST_1 + b"</nmaprun>")

    def test_no_host_finished(self):
        report = NmapOutputParser.salvage_partial(_HEADER + b"<host><status")
        self.assertEqual(report, _HEADER + b"</nmaprun>")

    def test_nothing_written(self):
        for stdout in (None, b"", b"<?xml version"):
            report = NmapOutputParser.salvage_partial(stdout)
            self.assertIn(b"<nmaprun", report)

    def test_partial_scan_is_warning_with_the_rest_not_scanned(self):
        result = NmapOutputParser.xmlparse(
            NmapOutputParser.salvage_partial(_KILLED),
            "asset-groups",
            _three_targets(),
            time_limit_seconds=540,
        )
        self.assertEqual(result["status"], WARNING)
        self.assertEqual(result["outputs"]["ports"], [22])
        states = {o.resolution.target: o for o in result["outcomes"]}
        self.assertTrue(states["10.0.0.1"].scanned)
        for target in ("10.0.0.2", "10.0.0.3"):
            self.assertEqual(states[target].state, NOT_SCANNED)
            self.assertEqual(states[target].reason, TIME_LIMIT_REASON)
        self.assertTrue(result["message"].startswith("nmap terminated at its 540 s"))
        self.assertIn("scan_timeout_seconds", result["message"])

    def test_nothing_scanned_is_error(self):
        result = NmapOutputParser.xmlparse(
            NmapOutputParser.salvage_partial(b""),
            "asset-groups",
            _three_targets(),
            time_limit_seconds=60,
        )
        self.assertEqual(result["status"], ERROR)
        self.assertTrue(all(not o.scanned for o in result["outcomes"]))


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "ConfigLoader")
class TestScanTimeLimit(unittest.TestCase):
    def _injector(self, m_configloader, m_helper, scan_timeout=None, threshold=None):
        m_configloader.return_value.nmap = ConfigLoaderNmap(scan_timeout=scan_timeout)
        helper = m_helper.return_value
        helper.api = MagicMock()
        helper.injector_logger = MagicMock()
        settings = {}
        if threshold is not None:
            settings = {
                "runtime_settings": [
                    {"key": THRESHOLD_SETTING_KEY, "value": str(threshold)}
                ]
            }
        helper.api.http_get.return_value = settings
        return module.OpenAEVNmap()

    def test_ceiling_resolution(self, m_configloader, m_helper, _):
        injector = self._injector(m_configloader, m_helper)
        self.assertEqual(injector.scan_timeout_for(None), DEFAULT_SCAN_TIMEOUT)
        self.assertEqual(injector.scan_timeout_for("120"), 120)
        injector = self._injector(m_configloader, m_helper, threshold=15)
        self.assertEqual(injector.scan_timeout_for(""), 840)
        self.assertEqual(injector.scan_timeout_for("7200"), 840)
        injector = self._injector(m_configloader, m_helper, scan_timeout=300)
        self.assertEqual(injector.scan_timeout_for(None), 300)
        self.assertEqual(injector.scan_timeout_for("200"), 200)

    def test_tuning_defaults_follow_the_deployment(self, m_configloader, m_helper, _):
        injector = self._injector(m_configloader, m_helper)
        self.assertEqual(injector.tuning_defaults(), SAFE_DEFAULTS)

    @patch.object(module.subprocess, "run")
    def test_timeout_keeps_partial_results_and_sends_traces(
        self, m_run, m_configloader, m_helper, _
    ):
        injector = self._injector(m_configloader, m_helper, scan_timeout=60)
        target_results = _three_targets()
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.contract_id = TCP_SYN_SCAN_CONTRACT
        message_data.selector_key = "asset-groups"
        message_data.target_results = target_results
        message_data.get_targets.return_value = target_results.targets
        message_data.scan_options = {}
        message_data.scan_timeout = None
        m_run.side_effect = subprocess.TimeoutExpired(
            cmd="nmap", timeout=60, output=_KILLED, stderr=b""
        )

        result = injector.nmap_execution(1, message_data)

        args, kwargs = m_run.call_args
        self.assertEqual(kwargs["timeout"], 60)
        self.assertEqual(_flag(args[0], "--host-timeout"), "300s")
        self.assertEqual(_flag(args[0], "--max-retries"), "2")
        self.assertEqual(result["status"], WARNING)
        traces = [
            c.kwargs["data"]
            for c in m_helper.return_value.api.inject.execution_callback.call_args_list
        ]
        per_target = {
            tuple(t.get("execution_context_identifiers") or ()): t for t in traces
        }
        self.assertIn("host up", per_target[("a1",)]["execution_message"])
        for asset in ("a2", "a3"):
            self.assertIn(TIME_LIMIT_REASON, per_target[(asset,)]["execution_message"])


if __name__ == "__main__":
    unittest.main()
