import unittest
from unittest.mock import ANY, MagicMock, patch, sentinel

import nmap.openaev_nmap as module

daemon_config_data = {
    "openaev_url": "http://fake.url",
    "openaev_token": "my_awesome_token",
    "injector_type": "network",
}


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module.ConfigLoader, "to_daemon_config", return_value=daemon_config_data)
class TestOpenAEVNmap(unittest.TestCase):
    def test_openaev_nmap_init(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        self.assertIsNotNone(injector.helper)
        self.assertIsInstance(injector.signature_manager, module.SignatureManager)
        self.assertEqual(injector.current_inject_id, "")
        self.assertEqual(injector.current_selector_key, "")
        self.assertEqual(injector.current_selector_property, "")
        self.assertEqual(injector.current_assets, [])
        self.assertIsNone(injector.current_target_results)

    @patch.object(module.Targets, "extract_targets")
    def test_openaev_nmap_update_current_elements(
        self, m_extract_targets, m_to_daemon_config, m_helper, _
    ):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        m_extract_targets.return_value = sentinel.target_results
        data = {
            "injection": {
                "inject_id": sentinel.inject_id,
                "inject_content": {
                    "expectations": [
                        {"expectation_type": "DETECTION"},
                        {"expectation_type": "PREVENTION"},
                    ],
                    module.TARGET_SELECTOR_KEY: "assets",
                    module.TARGET_PROPERTY_SELECTOR_KEY: "automatic",
                },
            },
            "assets": [sentinel.asset],
        }

        injector.update_current_elements(data)

        self.assertIsNotNone(injector.helper)
        self.assertIsInstance(injector.signature_manager, module.SignatureManager)
        self.assertEqual(injector.current_inject_id, sentinel.inject_id)
        self.assertEqual(injector.current_selector_key, "assets")
        self.assertEqual(injector.current_selector_property, "automatic")
        self.assertEqual(injector.current_assets, [sentinel.asset])
        self.assertEqual(injector.current_target_results, sentinel.target_results)
        m_extract_targets.assert_called_with(
            "assets",
            "automatic",
            data,
            injector.helper,
        )
        self.assertEqual(
            injector.current_expectation_types, ["DETECTION", "PREVENTION"]
        )

    def test_openaev_nmap_get_targets(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        target_results = MagicMock()
        targets = MagicMock()
        target_results.targets = targets
        injector = module.OpenAEVNmap()
        injector.current_target_results = target_results

        _targets = injector.get_targets()

        self.assertEqual(_targets, targets)

    def test_openaev_nmap_get_targets_no_targets(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        target_results = MagicMock()
        target_results.targets = []
        injector = module.OpenAEVNmap()
        injector.current_target_results = target_results
        injector.current_selector_property = "automatic"

        with self.assertRaises(ValueError) as context:
            injector.get_targets()
        self.assertEqual(
            str(context.exception), "No target identified for the property Automatic"
        )

    def test_openaev_nmap_build_target_meta(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()
        current_assets = [
            {"asset_id": "deadbeef"},
            {"asset_id": "baadcafe", "asset_agents": [{"agent_id": "f0cacc1a"}]},
            {"asset_group_id": "000ff1ce"},
        ]
        injector.current_assets = current_assets

        target_meta = injector.build_target_meta()

        self.assertEqual(
            target_meta,
            [
                {"agent": None, "asset": "deadbeef", "asset_group": None},
                {"agent": "f0cacc1a", "asset": "baadcafe", "asset_group": None},
                {"agent": None, "asset": None, "asset_group": "000ff1ce"},
            ],
        )

    @patch.object(module.NmapOutputParser, "parse")
    @patch.object(module.jc, "parse")
    @patch.object(module.subprocess, "run")
    @patch.object(module.Targets, "build_execution_message")
    @patch.object(module.NmapCommandBuilder, "build_args")
    def test_openaev_nmap_execution(
        self,
        m_build_args,
        m_build_execution_message,
        m_subprocess_run,
        m_jc_parse,
        m_parse,
        m_to_daemon_config,
        m_helper,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()

        start = 1
        data = {
            "injection": {
                "inject_injector_contract": {
                    "injector_contract_id": "my-current-contract-id",
                }
            }
        }
        targets = [sentinel.id]

        nmap_output = injector.nmap_execution(start, data, targets)

        m_build_args.assert_called_once_with("my-current-contract-id", targets)
        m_build_execution_message.assert_called_once_with(
            selector_key=injector.current_selector_key,
            data=data,
            command_args=m_build_args.return_value,
        )
        m_helper.return_value.api.inject.execution_callback.assert_called_with(
            inject_id=injector.current_inject_id,
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
        m_jc_parse.assert_called_once_with(
            "xml", m_subprocess_run.return_value.stdout.decode.return_value
        )
        m_parse.assert_called_once_with(
            data, m_jc_parse.return_value, injector.current_target_results
        )
        self.assertEqual(nmap_output, m_parse.return_value)

    @patch.object(module.OpenAEVNmap, "build_target_meta")
    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    @patch.object(module.OpenAEVNmap, "get_targets")
    @patch.object(module.OpenAEVNmap, "update_current_elements")
    def test_openaev_nmap_process_message(
        self,
        m_update_current_elements,
        m_get_targets,
        m_build_network_configs,
        m_signaturemanager,
        m_nmap_execution,
        m_build_target_meta,
        m_to_daemon_config,
        m_helper,
        _,
    ):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        m_nmap_execution.return_value = {
            "message": "Ceci n'est pas une pipe",
            "outputs": {
                "ports": [1, 2, 3, 4],
                "scan_results": ["result0", "result1", "result2", "result3"],
            },
        }
        injector.curent_inject_id = "deadbeef"
        data = MagicMock()

        injector.process_message(data)

        m_update_current_elements.assert_called_once_with(data)
        m_get_targets.assert_called_once()
        m_build_network_configs.assert_called_once_with(m_get_targets.return_value)
        m_signaturemanager.return_value.compile_pre_execution_signatures.assert_called_once_with(
            m_build_network_configs.return_value
        )
        injector.helper.api.inject.execution_reception.assert_called_once_with(
            inject_id=injector.current_inject_id, data={"tracking_total_count": 1}
        )
        m_nmap_execution(ANY, data, m_get_targets.return_value)
        m_signaturemanager.return_valuecompile_post_execution_signatures(
            m_signaturemanager.return_valuecompile_pre_execution_signatures.return_value,
            {
                "error_info": None,
                "extra_signatures": {
                    "ports_discovered": [],
                    "services_discovered": [],
                },
            },
        )
        m_build_target_meta.assert_called_once()
        injector.helper.api.inject.execution_callback.assert_called_once_with(
            inject_id=injector.current_inject_id, data=ANY
        )
        m_signaturemanager.return_value.build_payload.assert_called_once_with(
            m_signaturemanager.return_value.compile_post_execution_signatures.return_value,
            m_build_target_meta.return_value,
            expectation_types=injector.current_expectation_types,
        )
        m_signaturemanager.return_value.send_signatures.assert_called_once_with(
            inject_id=injector.current_inject_id,
            phase="execution_complete",
            signatures=m_signaturemanager.return_value.build_payload.return_value,
        )

    def test_openaev_nmap_start(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNmap()

        injector.start()

        injector.helper.listen.assert_called_with(
            message_callback=injector.process_message
        )
