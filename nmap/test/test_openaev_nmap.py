import threading
import unittest
from unittest.mock import ANY, MagicMock, patch

from pyoaev.exceptions import OpenAEVUpdateError

import nmap.openaev_nmap as module


def _not_found():
    return OpenAEVUpdateError("Inject not found", 404, b"")


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "MessageData", autospec=True)
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "ConfigLoader")
class TestOpenAEVNmap(unittest.TestCase):
    def test_openaev_nmap_init(self, m_configloader, m_helper, m_msgdata, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        self.assertIsNotNone(injector.helper)
        self.assertIsInstance(injector.signature_manager, module.SignatureManager)

    @patch.object(module.NmapOutputParser, "xmlparse")
    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_xmlparse,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()

        start = 1
        message_data = MagicMock()
        # No asset-backed targets -> the per-target trace helper is a no-op, so the
        # last execution_callback stays the global command_execution trace below.
        message_data.target_results.ip_to_asset_id_map = {}

        nmap_output = injector.nmap_execution(start, message_data)

        m_build_args.assert_called_once_with(
            message_data.contract_id,
            message_data.get_targets.return_value,
            message_data.scan_options,
            defaults=injector.tuning_defaults(),
        )
        m_build_execution_message.assert_called_once_with(
            selector_key=message_data.selector_key,
            data=message_data.raw_data,
            command_args=m_build_args.return_value,
            target_results=message_data.target_results,
        )
        m_helper.return_value.api.inject.execution_callback.assert_called_with(
            inject_id=message_data.inject_id,
            data={
                "execution_message": m_build_execution_message.return_value,
                "execution_status": "INFO",
                "execution_duration": ANY,
                "execution_action": "command_execution",
            },
        )
        m_subprocess_run.assert_called_once_with(
            m_build_args.return_value,
            timeout=ANY,
            on_host=ANY,
        )
        m_xmlparse.assert_called_once_with(
            m_subprocess_run.return_value.stdout,
            message_data.selector_key,
            message_data.target_results,
            stderr=m_subprocess_run.return_value.stderr,
            exit_code=m_subprocess_run.return_value.returncode,
        )
        self.assertEqual(nmap_output, m_xmlparse.return_value)

    @patch.object(module.NmapOutputParser, "xmlparse")
    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_reports_missed_targets_as_warning(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_xmlparse,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        from injector_common.outcomes import NOT_SCANNED, TargetOutcome
        from injector_common.targets import TargetResolution

        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.target_results.ip_to_asset_id_map = {}
        miss = TargetOutcome(
            TargetResolution(
                target="does-not-exist.invalid", asset_id="a1", asset_name="web-01"
            ),
            NOT_SCANNED,
            reason="hostname did not resolve",
        )
        m_xmlparse.return_value = {"message": "m", "outputs": {}, "outcomes": [miss]}

        injector.nmap_execution(1, message_data)

        calls = m_helper.return_value.api.inject.execution_callback.call_args_list
        warnings = [
            c for c in calls if c.kwargs["data"]["execution_status"] == "WARNING"
        ]
        self.assertEqual(len(warnings), 1)
        data = warnings[0].kwargs["data"]
        self.assertEqual(
            data["execution_message"],
            "does-not-exist.invalid (asset web-01): not scanned, "
            "hostname did not resolve",
        )
        self.assertEqual(data["execution_context_identifiers"], ["a1"])
        self.assertEqual(data["execution_action"], "command_execution")

    @staticmethod
    def _group_of_three(seen_ips):
        from injector_common.targets import Targets

        assets = [
            {"asset_id": f"a{i}", "asset_name": f"web-0{i}", "asset_seen_ip": ip}
            for i, ip in enumerate(seen_ips, start=1)
        ]
        data = {"injection": {"inject_content": {}}, "assets": assets}
        return Targets.extract_targets("asset-groups", "seen_ip", data, MagicMock())

    def _run_execution(self, m_subprocess_run, m_helper, target_results):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.selector_key = "assets"
        message_data.target_results = target_results
        message_data.get_targets.return_value = target_results.targets
        m_subprocess_run.return_value = MagicMock(
            stdout=(
                b'<?xml version="1.0"?><nmaprun scanner="nmap"><host>'
                b'<status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                b'<hostnames/><ports><port protocol="tcp" portid="22">'
                b'<state state="open"/><service name="ssh"/></port></ports>'
                b"</host></nmaprun>"
            ),
            stderr=b"",
            returncode=0,
        )
        result = injector.nmap_execution(1, message_data)
        calls = m_helper.return_value.api.inject.execution_callback.call_args_list
        return result, [c.kwargs["data"] for c in calls]

    @patch.object(module, "run_nmap")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_reports_skipped_assets(
        self, m_build_args, m_subprocess_run, m_configloader, m_helper, m_msgdata, _
    ):
        # Acceptance (a): one valid seen IP, one missing, one loopback.
        m_build_args.return_value = ["nmap", "10.0.0.1"]
        target_results = self._group_of_three(["10.0.0.1", None, "127.0.0.1"])

        result, traces = self._run_execution(m_subprocess_run, m_helper, target_results)

        # One host scanned.
        m_subprocess_run.assert_called_once()
        skipped_traces = [
            t
            for t in traces
            if t["execution_status"] == "WARNING"
            and "(target property" in t["execution_message"]
        ]
        self.assertEqual(
            [
                (t["execution_status"], t["execution_context_identifiers"])
                for t in skipped_traces
            ],
            [("WARNING", ["a2"]), ("WARNING", ["a3"])],
        )
        self.assertEqual(
            [t["execution_message"] for t in skipped_traces],
            [
                "web-02: not scanned, no seen IP (target property seen_ip)",
                "web-03: not scanned, seen IP 127.0.0.1 is loopback "
                "(target property seen_ip)",
            ],
        )
        self.assertEqual(result["status"], "WARNING")
        self.assertIn("2 of 3 assets skipped", result["message"])
        # The command execution message carries the summary too.
        self.assertIn("2 of 3 assets skipped", traces[0]["execution_message"])

    @patch.object(module, "run_nmap")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_without_skipped_assets_is_unchanged(
        self, m_build_args, m_subprocess_run, m_configloader, m_helper, m_msgdata, _
    ):
        # Acceptance (c): every asset valid, no skipped trace, status unchanged.
        from injector_common.targets import Targets

        m_build_args.return_value = ["nmap", "10.0.0.1"]
        data = {
            "injection": {"inject_content": {}},
            "assets": [{"asset_id": "a1", "asset_seen_ip": "10.0.0.1"}],
        }
        target_results = Targets.extract_targets(
            "asset-groups", "seen_ip", data, MagicMock()
        )

        result, traces = self._run_execution(m_subprocess_run, m_helper, target_results)

        self.assertFalse(
            any("(target property" in t["execution_message"] for t in traces)
        )
        self.assertEqual(
            [t["execution_status"] for t in traces], ["INFO", "INFO", "EXECUTED"]
        )
        self.assertEqual(result["status"], "EXECUTED")
        self.assertNotIn("skipped", result["message"])

    @patch.object(module.NmapOutputParser, "xmlparse")
    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_emits_per_target_traces(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_xmlparse,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()

        from injector_common.outcomes import HOST_DOWN, HOST_UP, TargetOutcome
        from injector_common.targets import TargetResolution

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.get_targets.return_value = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        # Two asset-backed targets and one manual target (no asset id): only the
        # asset-backed ones get a target-scoped outcome trace, after the scan.
        m_xmlparse.return_value = {
            "message": "m",
            "outputs": {},
            "outcomes": [
                TargetOutcome(TargetResolution("10.0.0.1", "asset-1"), HOST_UP, 2),
                TargetOutcome(TargetResolution("10.0.0.2", "asset-2"), HOST_DOWN),
                TargetOutcome(TargetResolution("10.0.0.3"), HOST_UP, 1),
            ],
        }

        injector.nmap_execution(1, message_data)

        calls = m_helper.return_value.api.inject.execution_callback.call_args_list
        # The progress trace states the target count and the platform threshold.
        progress = calls[1].kwargs["data"]
        self.assertEqual(progress["execution_status"], "INFO")
        self.assertIn("3 target(s)", progress["execution_message"])
        self.assertIn(
            "inject.execution.threshold.minutes", progress["execution_message"]
        )
        target_calls = [
            c for c in calls if c.kwargs["data"].get("execution_context_identifiers")
        ]
        self.assertEqual(
            [
                (
                    c.kwargs["data"]["execution_context_identifiers"],
                    c.kwargs["data"]["execution_status"],
                    c.kwargs["data"]["execution_message"],
                )
                for c in target_calls
            ],
            [
                (
                    ["asset-1"],
                    "EXECUTED",
                    "10.0.0.1 (asset asset-1): host up, 2 open ports",
                ),
                (
                    ["asset-2"],
                    "WARNING",
                    "10.0.0.2 (asset asset-2): host down or no response",
                ),
            ],
        )
        for c in target_calls:
            self.assertEqual(c.kwargs["data"]["execution_action"], "command_execution")

    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_nonzero_exit_with_report_keeps_results(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        """(c) nmap exits non-zero with a parseable report: the results are kept,
        the status is WARNING and the message carries the exit code."""
        from injector_common.targets import TargetExtractionResult

        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        message_data.selector_key = "assets"
        message_data.target_results = TargetExtractionResult(
            targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
        )
        m_subprocess_run.return_value = MagicMock(
            returncode=1,
            stdout=(
                b'<?xml version="1.0"?><nmaprun><host><status state="up" '
                b'reason="user-set"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                b'<ports><port protocol="tcp" portid="22"><state state="open"/>'
                b'<service name="ssh"/></port></ports></host></nmaprun>'
            ),
            stderr=b"some interruption",
        )

        result = injector.nmap_execution(1, message_data)

        self.assertEqual(result["status"], "WARNING")
        self.assertEqual(result["outputs"]["ports"], [22])
        self.assertIn("nmap exited with code 1", result["message"])

    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_nonzero_exit_without_report_raises(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        """(d) nmap exits non-zero with no report: CalledProcessError with stderr,
        which process_message turns into a global ERROR."""
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        m_subprocess_run.return_value = MagicMock(
            returncode=255, stdout=b"", stderr=b"QUITTING!"
        )

        with self.assertRaises(module.subprocess.CalledProcessError) as ctx:
            injector.nmap_execution(1, message_data)
        self.assertEqual(ctx.exception.returncode, 255)
        self.assertEqual(ctx.exception.stderr, b"QUITTING!")

    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution_nonzero_exit_empty_report_is_error(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        """(e) nmap exits non-zero and its report has the nmaprun header but no host:
        no target scanned, the status is ERROR and the message carries nmap's
        stderr."""
        from injector_common.targets import TargetExtractionResult

        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        message_data.selector_key = "assets"
        message_data.target_results = TargetExtractionResult(
            targets=["10.0.0.1"], ip_to_asset_id_map={"10.0.0.1": "a1"}
        )
        m_subprocess_run.return_value = MagicMock(
            returncode=1,
            stdout=b'<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>',
            stderr=b"NSE: failed to initialize the script engine\n",
        )

        result = injector.nmap_execution(1, message_data)

        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("nmap exited with code 1, no target scanned", result["message"])
        self.assertIn(
            "nmap stderr:\nNSE: failed to initialize the script engine",
            result["message"],
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_nothing_scanned_completes_error(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        """A parsed report with no target scanned on a non-zero exit completes the
        inject ERROR with the message and the exit code in the error info."""
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        message = (
            "0/1 targets scanned, 0 up, 1 missed, 0 open ports "
            "(nmap exited with code 1, no target scanned)\n"
            "nmap stderr:\nNSE: failed to initialize the script engine"
        )
        m_nmap_execution.return_value = {
            "message": message,
            "outputs": {"scan_results": [], "ports": []},
            "outcomes": [],
            "status": "ERROR",
            "exit_code": 1,
        }

        injector.process_message(MagicMock())

        data = injector.helper.api.inject.execution_callback.call_args.kwargs["data"]
        self.assertEqual(data["execution_status"], "ERROR")
        self.assertEqual(data["execution_message"], message)
        self.assertEqual(data["execution_action"], "complete")
        m_signaturemanager.return_value.post_execution_updates.assert_called_once_with(
            m_executiondetails.return_value,
            m_signaturemanager.return_value.build_execution_signatures.return_value,
            {"error_info": {"exit_code": 1}},
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data

        m_nmap_execution.return_value = {
            "message": "Ceci n'est pas une pipe",
            "outputs": {
                "ports": [1, 2, 3, 4],
                "scan_results": ["result0", "result1", "result2", "result3"],
            },
        }
        extra_data = {
            "ports_discovered": [1, 2, 3, 4],
            "services_discovered": ["result0", "result1", "result2", "result3"],
        }
        data = MagicMock()

        injector.process_message(data)

        m_msgdata.assert_called_once_with(data, m_helper.return_value)
        message_data.get_targets.assert_called_once()
        m_build_network_configs.assert_called_once_with(
            message_data.get_targets.return_value
        )
        m_signaturemanager.return_value.build_execution_signatures.assert_called_once_with(
            m_build_network_configs.return_value
        )
        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id=message_data.inject_id, data={"tracking_total_count": 1}
        )
        m_nmap_execution.assert_called_once_with(ANY, message_data)
        m_signaturemanager.return_value.post_execution_updates.assert_called_once_with(
            m_executiondetails.return_value,
            m_signaturemanager.return_value.build_execution_signatures.return_value,
            {
                "error_info": None,
            },
        )
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id=message_data.inject_id, data=ANY
        )
        m_signaturemanager.return_value.build_payload.assert_called_once_with(
            execution_signatures=m_signaturemanager.return_value.build_execution_signatures.return_value,
            targets_meta=message_data.targets_meta,
            expectation_types=message_data.expectation_types,
            extra_signatures=module.ExtraSignatureData(
                detection=extra_data,
                prevention=extra_data,
                vulnerability={},
            ),
        )
        m_signaturemanager.return_value.send_signatures.assert_called_once_with(
            inject_id=message_data.inject_id,
            execution_details=m_executiondetails.return_value,
            signatures=m_signaturemanager.return_value.build_payload.return_value,
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_failure(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data

        m_nmap_execution.side_effect = module.subprocess.CalledProcessError(
            returncode=42, cmd="", stderr=b"this is an error message"
        )

        data = MagicMock()

        injector.process_message(data)

        m_msgdata.assert_called_once_with(data, m_helper.return_value)
        message_data.get_targets.assert_called_once()
        m_build_network_configs.assert_called_once_with(
            message_data.get_targets.return_value
        )
        m_signaturemanager.return_value.build_execution_signatures.assert_called_once_with(
            m_build_network_configs.return_value
        )
        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id=message_data.inject_id, data={"tracking_total_count": 1}
        )
        m_nmap_execution.assert_called_once_with(ANY, message_data)
        m_signaturemanager.return_value.post_execution_updates.assert_called_once_with(
            m_executiondetails.return_value,
            m_signaturemanager.return_value.build_execution_signatures.return_value,
            {
                "error_info": {
                    "exit_code": 42,
                },
            },
        )
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id=message_data.inject_id, data=ANY
        )
        m_signaturemanager.return_value.build_payload.assert_called_once_with(
            execution_signatures=m_signaturemanager.return_value.build_execution_signatures.return_value,
            targets_meta=message_data.targets_meta,
            expectation_types=message_data.expectation_types,
            extra_signatures=module.ExtraSignatureData(
                detection={},
                prevention={},
                vulnerability={},
            ),
        )
        m_signaturemanager.return_value.send_signatures.assert_called_once_with(
            inject_id=message_data.inject_id,
            execution_details=m_executiondetails.return_value,
            signatures=m_signaturemanager.return_value.build_payload.return_value,
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_concurrent_no_id_mix(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # Regression test for the race condition in #338: two injections
        # processed concurrently on the SAME injector instance must each keep
        # their own inject id. Before the fix, per-message state lived on the
        # instance (self.current_inject_id, ...) and could be overwritten by a
        # second message mid-processing, mixing the ids in the callbacks.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data_a = MagicMock()
        message_data_a.inject_id = "inject-a"
        message_data_b = MagicMock()
        message_data_b.inject_id = "inject-b"
        m_msgdata.side_effect = [message_data_a, message_data_b]

        # Force both threads to be inside process_message at the same time so a
        # shared-state implementation would clobber the first inject id. The join
        # timeout is deliberately larger than the barrier timeout so that, under
        # slow CI scheduling, a thread that reaches the barrier late still has
        # time to finish before join() gives up (otherwise the test could flake).
        barrier_timeout = 5
        join_timeout = barrier_timeout + 5
        barrier = threading.Barrier(2)
        # Only appended once a thread gets past the barrier: len() == 2 proves
        # both calls genuinely overlapped instead of running one after another.
        overlapped = []

        def blocking_execution(_start, msg_data):
            barrier.wait(timeout=barrier_timeout)
            overlapped.append(msg_data.inject_id)
            return {
                "message": "ok",
                "outputs": {"ports": [], "scan_results": []},
            }

        m_nmap_execution.side_effect = blocking_execution

        errors = []

        def run(msg):
            try:
                injector.process_message(msg)
            except Exception as exc:  # noqa: BLE001 - surface thread failures
                errors.append(exc)

        threads = [
            threading.Thread(target=run, args=(MagicMock(),)),
            threading.Thread(target=run, args=(MagicMock(),)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=join_timeout)

        # The threads must have actually finished (no hang / broken barrier) and
        # neither call may have raised for the assertions below to be meaningful.
        for thread in threads:
            self.assertFalse(
                thread.is_alive(), "process_message thread did not finish in time"
            )
        self.assertEqual(errors, [])
        self.assertEqual(
            len(overlapped),
            2,
            "both process_message calls must overlap at the barrier",
        )

        reception_ids = sorted(
            call.kwargs["inject_id"]
            for call in injector.helper.api.inject.execution_reception.call_args_list
        )
        self.assertEqual(reception_ids, ["inject-a", "inject-b"])

        send_ids = sorted(
            call.kwargs["inject_id"]
            for call in m_signaturemanager.return_value.send_signatures.call_args_list
        )
        self.assertEqual(send_ids, ["inject-a", "inject-b"])

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_message_data_failure(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # If MessageData construction raises (invalid payload, no targets, ...),
        # process_message must not let the exception escape: it reports a
        # terminal ERROR callback resolved from the raw payload instead.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        m_msgdata.side_effect = ValueError("No target identified")
        data = {"injection": {"inject_id": "inject-x"}}

        injector.process_message(data)

        m_nmap_execution.assert_not_called()
        m_build_network_configs.assert_not_called()
        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id="inject-x", data={"tracking_total_count": 1}
        )
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id="inject-x", data=ANY
        )
        callback_data = injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
        self.assertEqual(callback_data["execution_status"], "ERROR")
        self.assertEqual(callback_data["execution_action"], "complete")
        self.assertIn("Pre-execution failure", callback_data["execution_message"])
        m_signaturemanager.return_value.send_signatures.assert_not_called()

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_every_asset_skipped(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # Acceptance (b): every asset invalid -> ERROR, nmap not run, one WARNING
        # trace per skipped asset before the completion.
        from nmap.models.data import MessageData

        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        target_results = self._group_of_three([None, "127.0.0.1", "0.0.0.0"])
        message_data = MagicMock()
        message_data.target_results = target_results
        message_data.get_targets.side_effect = lambda: MessageData.get_targets(
            message_data
        )
        message_data.selector_property = "seen_ip"
        message_data._selector_property_label.return_value = "Seen IP"
        m_msgdata.return_value = message_data
        data = {"injection": {"inject_id": "inject-z"}}

        injector.process_message(data)

        m_nmap_execution.assert_not_called()
        m_build_network_configs.assert_not_called()
        traces = [
            c.kwargs["data"]
            for c in injector.helper.api.inject.execution_callback.call_args_list
        ]
        self.assertEqual(
            [(t["execution_status"], t["execution_action"]) for t in traces],
            [("WARNING", "command_execution")] * 3 + [("ERROR", "complete")],
        )
        self.assertEqual(
            [t["execution_context_identifiers"] for t in traces[:3]],
            [["a1"], ["a2"], ["a3"]],
        )
        self.assertIn("3 of 3 assets skipped", traces[3]["execution_message"])
        self.assertIn(
            "No target identified for the property Seen IP",
            traces[3]["execution_message"],
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_no_targets_failure(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # get_targets() raising (empty targets) is also a pre-execution failure
        # and must produce a terminal ERROR callback without running nmap.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.get_targets.side_effect = ValueError(
            "No target identified for the property Hostname"
        )
        m_msgdata.return_value = message_data
        data = {"injection": {"inject_id": "inject-y"}}

        injector.process_message(data)

        m_nmap_execution.assert_not_called()
        m_build_network_configs.assert_not_called()
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id="inject-y", data=ANY
        )
        callback_data = injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
        self.assertEqual(callback_data["execution_status"], "ERROR")
        self.assertIn("Pre-execution failure", callback_data["execution_message"])
        m_signaturemanager.return_value.send_signatures.assert_not_called()

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_process_message_unresolvable_inject_id(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # When MessageData construction fails AND the payload has no resolvable
        # inject id, process_message must still not raise: there is nowhere to
        # address a terminal callback, so it logs and returns instead of letting
        # the exception escape (which would defeat the pre-execution guard).
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        m_msgdata.side_effect = KeyError("injection")
        data = {}

        injector.process_message(data)

        m_nmap_execution.assert_not_called()
        m_build_network_configs.assert_not_called()
        injector.helper.api.inject.execution_reception.assert_not_called()
        injector.helper.api.inject.execution_callback.assert_not_called()
        m_signaturemanager.return_value.send_signatures.assert_not_called()
        injector.helper.injector_logger.error.assert_called()

    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    @patch.object(module, "run_nmap")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_inject_deleted_before_scan_aborts(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # The inject is deleted after the command_execution callback: the progress
        # trace sent before the scan answers 404. nmap must not run, no outcome
        # trace is sent, one abort line is logged and nothing escapes.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.get_targets.return_value = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        m_msgdata.return_value = message_data
        injector.helper.api.inject.execution_callback.side_effect = [
            None,  # global command_execution trace
            _not_found(),  # progress trace, before the scan
        ]

        injector.process_message({"injection": {"inject_id": "inject-id"}})

        m_subprocess_run.assert_not_called()
        self.assertEqual(injector.helper.api.inject.execution_callback.call_count, 2)
        m_signaturemanager.return_value.send_signatures.assert_not_called()
        injector.helper.injector_logger.warning.assert_called_once_with(
            "inject inject-id deleted, aborting"
        )
        injector.helper.injector_logger.error.assert_not_called()

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_inject_deleted_on_final_callback_aborts(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        m_nmap_execution.return_value = {"message": "done", "outputs": {}}
        injector.helper.api.inject.execution_callback.side_effect = _not_found()

        injector.process_message({"injection": {"inject_id": "inject-id"}})

        m_signaturemanager.return_value.send_signatures.assert_not_called()
        injector.helper.injector_logger.warning.assert_called_once_with(
            "inject inject-id deleted, aborting"
        )

    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nmap_non_404_on_final_callback_still_raises(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nmap_execution,
        m_configloader,
        m_helper,
        m_msgdata,
        _,
    ):
        # Any other platform error keeps today's behaviour.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        m_nmap_execution.return_value = {"message": "done", "outputs": {}}
        injector.helper.api.inject.execution_callback.side_effect = OpenAEVUpdateError(
            "boom", 500, b""
        )

        with self.assertRaises(OpenAEVUpdateError):
            injector.process_message({"injection": {"inject_id": "inject-id"}})
        injector.helper.injector_logger.warning.assert_not_called()

    def test_openaev_nmap_start(self, m_configloader, m_helper, m_msgdata, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        injector.start()

        injector.helper.listen.assert_called_with(
            message_callback=injector.process_message
        )
