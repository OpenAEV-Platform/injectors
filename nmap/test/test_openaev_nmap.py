import threading
import unittest
from unittest.mock import ANY, MagicMock, patch

import nmap.openaev_nmap as module


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
    @patch.object(module.subprocess, "run")
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

        nmap_output = injector.nmap_execution(start, message_data)

        m_build_args.assert_called_once_with(
            message_data.contract_id, message_data.get_targets.return_value
        )
        m_build_execution_message.assert_called_once_with(
            selector_key=message_data.selector_key,
            data=message_data.raw_data,
            command_args=m_build_args.return_value,
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
            m_build_args.return_value, check=True, capture_output=True
        )
        m_xmlparse.assert_called_once_with(
            m_subprocess_run.return_value.stdout,
            message_data.selector_key,
            message_data.target_results,
        )
        self.assertEqual(nmap_output, m_xmlparse.return_value)

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
        # shared-state implementation would clobber the first inject id.
        barrier = threading.Barrier(2)
        # Only appended once a thread gets past the barrier: len() == 2 proves
        # both calls genuinely overlapped instead of running one after another.
        overlapped = []

        def blocking_execution(_start, msg_data):
            barrier.wait(timeout=5)
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
            except BaseException as exc:  # noqa: BLE001 - surface thread failures
                errors.append(exc)

        threads = [
            threading.Thread(target=run, args=(MagicMock(),)),
            threading.Thread(target=run, args=(MagicMock(),)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

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

    def test_openaev_nmap_start(self, m_configloader, m_helper, m_msgdata, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        injector.start()

        injector.helper.listen.assert_called_with(
            message_callback=injector.process_message
        )
