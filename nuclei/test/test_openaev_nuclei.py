import json
import unittest
from unittest.mock import ANY, MagicMock, patch

import nuclei.openaev_nuclei as module


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "MessageData", autospec=True)
@patch.object(module, "NucleiOutputParser")
@patch.object(module, "NucleiProcess")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "OpenAEVConfigHelper")
@patch.object(module, "ConfigLoader")
class TestOpenAEVNuclei(unittest.TestCase):
    def test_openaev_nuclei_init(
        self,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()

        self.assertIsNotNone(injector.helper)
        self.assertIsNotNone(injector.config_loader)
        self.assertEqual(injector.parser, m_parser.return_value)

    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module, "NucleiCommandBuilder")
    def test_openaev_nuclei_execution(
        self,
        m_builder,
        m_build_execution_message,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNuclei()

        start = 1
        message_data = MagicMock()
        message_data.get_targets.return_value = ["1.1.1.1"]
        m_builder.return_value.build.return_value = ["nuclei", "-jsonl"]

        nuclei_output = injector.nuclei_execution(start, message_data)

        m_builder.assert_called_once_with(
            nuclei_configs=injector.config_loader.nuclei,
            contract_id=message_data.contract_id,
            content=message_data.inject_content,
            targets=message_data.get_targets.return_value,
        )
        m_build_execution_message.assert_called_once_with(
            selector_key=message_data.selector_key,
            data=message_data.raw_data,
            command_args=m_builder.return_value.build.return_value,
        )
        m_helper.return_value.api.inject.execution_callback.assert_called_once_with(
            inject_id=message_data.inject_id,
            data={
                "execution_message": m_build_execution_message.return_value,
                "execution_status": "INFO",
                "execution_duration": ANY,
                "execution_action": "command_execution",
            },
        )
        m_nucleiprocess.nuclei_execute.assert_called_once_with(
            m_builder.return_value.build.return_value, b"1.1.1.1\n"
        )
        m_parser.return_value.parse.assert_called_once_with(
            m_nucleiprocess.nuclei_execute.return_value.stdout.decode.return_value,
            message_data.target_results.ip_to_asset_id_map,
        )
        self.assertEqual(nuclei_output, m_parser.return_value.parse.return_value)

    @patch.object(module.OpenAEVNuclei, "nuclei_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nuclei_process_message(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nuclei_execution,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data

        m_nuclei_execution.return_value = {
            "message": "all good",
            "outputs": {"vulnerabilities": ["cve-1", "cve-2"]},
        }
        data = MagicMock()

        injector.process_message(data)

        m_msgdata.assert_called_once_with(data, m_helper.return_value)
        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id=message_data.inject_id, data={"tracking_total_count": 1}
        )
        m_build_network_configs.assert_called_once_with(
            message_data.get_targets.return_value
        )
        m_signaturemanager.return_value.build_execution_signatures.assert_called_once_with(
            config=m_build_network_configs.return_value
        )
        m_nuclei_execution.assert_called_once_with(ANY, message_data)
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id=message_data.inject_id,
            data={
                "execution_message": "all good",
                "execution_status": "SUCCESS",
                "execution_duration": ANY,
                "execution_action": "complete",
                "execution_output_structured": json.dumps(
                    {"vulnerabilities": ["cve-1", "cve-2"]}
                ),
            },
        )
        m_signaturemanager.return_value.post_execution_updates.assert_called_once_with(
            execution_details=m_executiondetails.return_value,
            execution_signatures=m_signaturemanager.return_value.build_execution_signatures.return_value,
            tool_output={},
        )
        m_signaturemanager.return_value.build_payload.assert_called_once_with(
            execution_signatures=m_signaturemanager.return_value.build_execution_signatures.return_value,
            targets_meta=message_data.targets_meta,
            expectation_types=message_data.expectation_types,
            extra_signatures=module.ExtraSignatureData(
                vulnerability={
                    "cves_tested": [],
                    "cves_found_vulnerable": [],
                }
            ),
        )
        m_signaturemanager.return_value.send_signatures.assert_called_once_with(
            inject_id=message_data.inject_id,
            execution_details=m_executiondetails.return_value,
            signatures=m_signaturemanager.return_value.build_payload.return_value,
        )

    @patch.object(module.OpenAEVNuclei, "nuclei_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nuclei_process_message_pre_execute_failure(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_executiondetails,
        m_nuclei_execution,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()

        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data

        m_build_network_configs.side_effect = ValueError("No target identified")
        data = MagicMock()

        injector.process_message(data)

        m_build_network_configs.assert_called_once_with(
            message_data.get_targets.return_value
        )
        m_nuclei_execution.assert_not_called()
        callback_data = injector.helper.api.inject.execution_callback.call_args.kwargs[
            "data"
        ]
        self.assertEqual(callback_data["execution_status"], "ERROR")
        self.assertEqual(callback_data["execution_action"], "complete")
        self.assertIn("Pre-execution failure", callback_data["execution_message"])
        m_signaturemanager.return_value.send_signatures.assert_not_called()

    @patch.object(module.OpenAEVNuclei, "nuclei_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    def test_openaev_nuclei_process_message_message_data_failure(
        self,
        m_build_network_configs,
        m_signaturemanager,
        m_nuclei_execution,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        # If MessageData construction raises (invalid payload, no targets, ...),
        # process_message must not let the exception escape: it reports a
        # terminal ERROR callback resolved from the raw payload instead.
        m_helper.return_value.injector_logger = MagicMock()
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()

        m_msgdata.side_effect = ValueError("No target identified")
        data = {"injection": {"inject_id": "inject-x"}}

        injector.process_message(data)

        m_nuclei_execution.assert_not_called()
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

    def test_openaev_nuclei_start(
        self,
        m_configloader,
        m_confighelper,
        m_helper,
        m_nucleiprocess,
        m_parser,
        m_msgdata,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNuclei()

        with patch.object(module, "ExternalContractsScheduler"):
            injector.start()

        injector.helper.listen.assert_called_with(
            message_callback=injector.process_message
        )


if __name__ == "__main__":
    unittest.main()
