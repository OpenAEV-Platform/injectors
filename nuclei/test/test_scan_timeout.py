"""Scan ceiling of the Nuclei injector (OpenAEV-Platform/injectors#569).

A scan terminated at its ceiling keeps the findings Nuclei wrote before the
kill and ends TIMEOUT with a partial message; the ceiling is settable per
inject and is derived from the platform inject execution threshold when the
deployment sets none.
"""

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import ANY, MagicMock, patch

from pyoaev.signatures.models import ExecutionDetails, ExecutionStatus, ToolOutput

import nuclei.openaev_nuclei as module
from nuclei.helpers.nuclei_output_parser import NucleiOutputParser

FINDING_1 = {
    "matcher-status": True,
    "host": "10.0.0.1",
    "info": {"severity": "high", "classification": {"cve-id": ["cve-2024-0001"]}},
}
FINDING_2 = {
    "matcher-status": True,
    "host": "10.0.0.2",
    "info": {"severity": "critical", "classification": {"cve-id": ["cve-2024-0002"]}},
}
PARTIAL_STDOUT = (json.dumps(FINDING_1) + "\n" + json.dumps(FINDING_2) + "\n").encode()


def _settings(minutes):
    return {
        "runtime_settings": [
            {"key": "agent_max_simultaneous_jobs", "value": "5"},
            {"key": module.THRESHOLD_SETTING_KEY, "value": str(minutes)},
        ]
    }


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "NucleiProcess")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "OpenAEVConfigHelper")
@patch.object(module, "ConfigLoader")
class TestScanTimeout(unittest.TestCase):
    def _injector(self, m_helper, deployment=None, settings=None):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNuclei()
        injector.config_loader.nuclei.scan_timeout = deployment
        if isinstance(settings, Exception):
            injector.helper.api.http_get.side_effect = settings
        else:
            injector.helper.api.http_get.return_value = settings or {}
        return injector

    # -- ceiling resolution --

    def test_per_inject_value_is_used(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(m_helper, deployment=540, settings=_settings(60))
        self.assertEqual(
            injector.scan_timeout_for({module.SCAN_TIMEOUT_FIELD: "1200"}), 1200
        )

    def test_absent_per_inject_value_uses_deployment(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(m_helper, deployment=900, settings=_settings(60))
        self.assertEqual(injector.scan_timeout_for({}), 900)
        self.assertEqual(
            injector.scan_timeout_for({module.SCAN_TIMEOUT_FIELD: ""}), 900
        )

    def test_unset_deployment_derives_from_platform_threshold(
        self, _cl, _ch, m_helper, _np, _i
    ):
        injector = self._injector(m_helper, deployment=None, settings=_settings(60))
        self.assertEqual(injector.scan_timeout_for({}), 60 * 60 - 60)

    def test_unknown_threshold_falls_back_to_default(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(
            m_helper, deployment=None, settings=RuntimeError("404 /settings")
        )
        self.assertEqual(injector.scan_timeout_for({}), module.DEFAULT_SCAN_TIMEOUT)
        injector.helper.injector_logger.warning.assert_called()

    def test_ceiling_capped_below_platform_threshold(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(m_helper, deployment=540, settings=_settings(10))
        self.assertEqual(
            injector.scan_timeout_for({module.SCAN_TIMEOUT_FIELD: "7200"}), 540
        )
        injector.helper.injector_logger.warning.assert_called()

    def test_invalid_per_inject_value_is_ignored(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(m_helper, deployment=300, settings={})
        for value in ("abc", "-5", "0", True, None):
            self.assertEqual(
                injector.scan_timeout_for({module.SCAN_TIMEOUT_FIELD: value}), 300
            )

    # -- the scan --

    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module, "NucleiCommandBuilder")
    def test_per_inject_timeout_passed_to_nuclei(
        self, m_builder, _bem, _cl, _ch, m_helper, m_process, _i
    ):
        injector = self._injector(m_helper, deployment=540, settings={})
        m_builder.return_value.build.return_value = ["nuclei", "-jsonl"]
        m_process.nuclei_execute.return_value.stdout = b""
        m_process.nuclei_execute.return_value.stderr = b""
        message_data = MagicMock()
        message_data.inject_content = {module.SCAN_TIMEOUT_FIELD: "1800"}
        message_data.get_targets.return_value = ["10.0.0.1"]
        message_data.target_results.ip_to_asset_id_map = {}

        injector.nuclei_execution(1, message_data)

        m_process.nuclei_execute.assert_called_once_with(
            ["nuclei", "-jsonl"], b"10.0.0.1\n", timeout=1800
        )

    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module, "NucleiCommandBuilder")
    def test_timeout_keeps_partial_findings(
        self, m_builder, _bem, _cl, _ch, m_helper, m_process, _i
    ):
        injector = self._injector(m_helper, deployment=540, settings={})
        injector.parser = NucleiOutputParser()
        m_builder.return_value.build.return_value = ["nuclei", "-jsonl"]
        m_process.nuclei_execute.side_effect = module.subprocess.TimeoutExpired(
            cmd="nuclei", timeout=540, output=PARTIAL_STDOUT, stderr=b"killed"
        )
        message_data = MagicMock()
        message_data.inject_content = {}
        message_data.get_targets.return_value = ["10.0.0.1", "10.0.0.2"]
        message_data.target_results.ip_to_asset_id_map = {
            "10.0.0.1": "asset-1",
            "10.0.0.2": "asset-2",
        }

        with self.assertRaises(module.ScanTimedOut) as ctx:
            injector.nuclei_execution(1, message_data)

        cves = ctx.exception.result["outputs"]["cve"]
        self.assertEqual(
            sorted(c["id"] for c in cves), ["CVE-2024-0001", "CVE-2024-0002"]
        )
        self.assertIn("540 s time limit", str(ctx.exception))
        self.assertIn("results partial (2 CVE(s)", str(ctx.exception))
        # No stats line on stderr: the coverage is said unknown (#576).
        self.assertIn("coverage unknown", str(ctx.exception))
        self.assertIn(
            "source: deployment variable NUCLEI_SCAN_TIMEOUT", str(ctx.exception)
        )

    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module, "NucleiCommandBuilder")
    def test_timeout_reports_coverage_at_cut_off(
        self, m_builder, _bem, _cl, _ch, m_helper, m_process, _i
    ):
        injector = self._injector(m_helper, deployment=None, settings=_settings(61))
        injector.parser = NucleiOutputParser()
        m_builder.return_value.build.return_value = ["nuclei", "-jsonl"]
        stats = {
            "duration": "0:59:58",
            "templates": "3100",
            "hosts": "193",
            "matched": "0",
            "requests": "1234567",
            "total": "3000000",
            "errors": "0",
            "percent": "41",
        }
        m_process.nuclei_execute.side_effect = module.subprocess.TimeoutExpired(
            cmd="nuclei",
            timeout=3600,
            output=b"",
            stderr=("[INF] start\n" + json.dumps(stats) + "\n").encode(),
        )
        message_data = MagicMock()
        message_data.inject_content = {}
        message_data.get_targets.return_value = ["10.0.0.1"]
        message_data.target_results.ip_to_asset_id_map = {"10.0.0.1": "asset-1"}

        with self.assertRaises(module.ScanTimedOut) as ctx:
            injector.nuclei_execution(1, message_data)

        message = str(ctx.exception)
        self.assertIn("3600 s time limit", message)
        self.assertIn(
            "source: platform inject execution threshold (61 min) minus 60 s", message
        )
        self.assertIn(
            "coverage at cut-off: 41% of requests (1,234,567 / 3,000,000), 193 "
            "hosts, 3,100 templates, 0:59:58 elapsed",
            message,
        )
        coverage = ctx.exception.result["outputs"][module.COVERAGE_KEY]
        self.assertEqual(coverage["requests"], 1234567)
        self.assertEqual(coverage["percent"], 41)
        traces = [
            c.kwargs["data"]["execution_message"]
            for c in injector.helper.api.inject.execution_callback.call_args_list
        ]
        # Start trace with the limit and its source, then the queued target.
        self.assertIn(
            "scan time limit: 3600 s (source: platform inject execution threshold "
            "(61 min) minus 60 s)",
            traces,
        )
        self.assertIn("target 10.0.0.1 queued for nuclei scan", traces)
        self.assertFalse(any("executed against" in t for t in traces))

    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module, "NucleiCommandBuilder")
    def test_completed_scan_reports_coverage(
        self, m_builder, _bem, _cl, _ch, m_helper, m_process, _i
    ):
        injector = self._injector(m_helper, deployment=900, settings={})
        injector.parser = NucleiOutputParser()
        m_builder.return_value.build.return_value = ["nuclei", "-jsonl"]
        stats = {
            "duration": "0:02:10",
            "templates": "10",
            "hosts": "2",
            "requests": "200",
            "total": "200",
            "errors": "0",
        }
        m_process.nuclei_execute.return_value.stdout = PARTIAL_STDOUT
        m_process.nuclei_execute.return_value.stderr = json.dumps(stats).encode()
        message_data = MagicMock()
        message_data.inject_content = {}
        message_data.get_targets.return_value = ["10.0.0.1", "10.0.0.2"]
        message_data.target_results.ip_to_asset_id_map = {}

        result = injector.nuclei_execution(1, message_data)

        self.assertIn("coverage: 100% of requests (200 / 200)", result["message"])
        self.assertIn("900 s time limit", result["message"])
        self.assertEqual(result["outputs"][module.COVERAGE_KEY]["hosts"], 2)
        self.assertEqual(len(result["outputs"]["cve"]), 2)

    def test_fallback_start_trace_is_a_warning(self, _cl, _ch, m_helper, _np, _i):
        injector = self._injector(
            m_helper, deployment=None, settings=RuntimeError("404 /settings")
        )
        limit = injector.scan_time_limit_for({})
        self.assertTrue(limit.fallback)
        module.send_scan_time_limit_trace(
            injector.helper, "inject-id", limit, module.DEPLOYMENT_VARIABLE, 0
        )
        data = injector.helper.api.inject.execution_callback.call_args.kwargs["data"]
        self.assertIn("Warning: scan time limit: 540 s", data["execution_message"])
        self.assertIn("NUCLEI_SCAN_TIMEOUT", data["execution_message"])
        self.assertIn(module.SCAN_TIMEOUT_FIELD, data["execution_message"])
        injector.helper.injector_logger.error.assert_called_once()

    # -- the terminal callback --

    @patch.object(module.OpenAEVNuclei, "nuclei_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    @patch.object(module, "MessageData", autospec=True)
    def _process_timeout(
        self,
        outputs,
        m_msgdata,
        _bnc,
        m_signatures,
        _ed,
        m_execution,
        m_helper,
    ):
        injector = self._injector(m_helper, deployment=540, settings={})
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        m_execution.side_effect = module.ScanTimedOut(
            "terminated, results partial", {"message": "", "outputs": outputs}
        )
        injector.process_message(MagicMock())
        callback = injector.helper.api.inject.execution_callback
        callback.assert_called_once_with(inject_id="inject-id", data=ANY)
        m_signatures.return_value.send_signatures.assert_called_once()
        return callback.call_args.kwargs["data"]

    def test_timeout_sends_partial_findings_and_terminal_status(
        self, _cl, _ch, m_helper, _np, _i
    ):
        cves = [
            {
                "id": "CVE-2024-0001",
                "asset_id": ["a1"],
                "host": ["h1"],
                "severity": "high",
            },
            {
                "id": "CVE-2024-0002",
                "asset_id": ["a2"],
                "host": ["h2"],
                "severity": "high",
            },
        ]
        data = self._process_timeout({"cve": cves, "others": []}, m_helper=m_helper)

        self.assertEqual(data["execution_status"], module.TIMEOUT_STATUS)
        self.assertEqual(data["execution_action"], "complete")
        self.assertIn("results partial", data["execution_message"])
        self.assertEqual(json.loads(data["execution_output_structured"])["cve"], cves)

    def test_timeout_without_cve_never_reads_as_not_vulnerable(
        self, _cl, _ch, m_helper, _np, _i
    ):
        data = self._process_timeout(
            {"cve": [], "others": [], "action_output": "x"}, m_helper=m_helper
        )

        self.assertEqual(data["execution_status"], module.TIMEOUT_STATUS)
        self.assertNotIn("cve", json.loads(data["execution_output_structured"]))

    # -- the signature callback (#577) --

    @patch.object(module.OpenAEVNuclei, "nuclei_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    @patch.object(module, "MessageData", autospec=True)
    def _signature_tool_output(
        self, side_effect, m_msgdata, _bnc, m_signatures, m_execution, m_helper
    ):
        injector = self._injector(m_helper, deployment=540, settings={})
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        m_execution.side_effect = side_effect
        injector.process_message(MagicMock())
        post = m_signatures.return_value.post_execution_updates
        post.assert_called_once()
        return post.call_args.kwargs["tool_output"]

    @staticmethod
    def _signature_status(tool_output):
        # The real pyoaev models, as SignatureManager.post_execution_updates
        # applies them to the execution details.
        details = ExecutionDetails()
        details.post_execution_update(
            ToolOutput.model_validate(tool_output), datetime.now(timezone.utc)
        )
        return details.execution_status

    def test_timeout_reaches_the_signature_layer_as_timeout(
        self, _cl, _ch, m_helper, _np, _i
    ):
        cves = [
            {"id": "CVE-2024-0002", "asset_id": ["a2"], "host": ["h2"]},
            {"id": "CVE-2024-0001", "asset_id": ["a1"], "host": ["h1"]},
        ]
        tool_output = self._signature_tool_output(
            module.ScanTimedOut(
                "terminated, results partial",
                {"message": "", "outputs": {"cve": cves, "others": []}},
            ),
            m_helper=m_helper,
        )

        self.assertNotIn("error_info", tool_output)
        self.assertEqual(
            tool_output["timeout_info"]["partial_results"],
            ["CVE-2024-0001", "CVE-2024-0002"],
        )
        self.assertEqual(self._signature_status(tool_output), ExecutionStatus.TIMEOUT)

    def test_timeout_without_findings_still_reads_timeout(
        self, _cl, _ch, m_helper, _np, _i
    ):
        tool_output = self._signature_tool_output(
            module.ScanTimedOut("terminated", {"message": "", "outputs": {}}),
            m_helper=m_helper,
        )

        self.assertEqual(tool_output, {"timeout_info": {"partial_results": []}})
        self.assertEqual(self._signature_status(tool_output), ExecutionStatus.TIMEOUT)

    def test_generic_failure_still_reads_error(self, _cl, _ch, m_helper, _np, _i):
        tool_output = self._signature_tool_output(
            RuntimeError("nuclei crashed"), m_helper=m_helper
        )

        self.assertEqual(tool_output, {"error_info": {"exit_code": 1}})
        self.assertEqual(self._signature_status(tool_output), ExecutionStatus.ERROR)


if __name__ == "__main__":
    unittest.main()
