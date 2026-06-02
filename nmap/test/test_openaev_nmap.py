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

    def test_openaev_nmap_get_targets(self, m_to_daemon_config, m_helper, _):
        m_helper.return_value.api = MagicMock()
        target_results = MagicMock()
        targets = MagicMock()
        target_results.targets = targets
        injector = module.OpenAEVNmap()
        injector.current_target_results = target_results

        _targets = injector.get_targets()

        self.assertEqual(_targets, targets)

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
