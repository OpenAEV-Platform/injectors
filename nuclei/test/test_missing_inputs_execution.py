import os
import tempfile
import unittest
from test.helpers.test_template_analysis import AUTHENTICATED_TEMPLATE
from unittest.mock import MagicMock, patch

import nuclei.openaev_nuclei as module


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "NucleiOutputParser")
@patch.object(module, "NucleiProcess")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "OpenAEVConfigHelper")
@patch.object(module, "ConfigLoader")
class MissingInputsExecutionTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        os.environ["NUCLEI_TEMPLATES_DIR"] = self._dir.name
        self.template = "CVE-2024-9264.yaml"
        with open(
            os.path.join(self._dir.name, self.template), "w", encoding="utf-8"
        ) as f:
            f.write(AUTHENTICATED_TEMPLATE)

    def tearDown(self):
        del os.environ["NUCLEI_TEMPLATES_DIR"]
        self._dir.cleanup()

    def _message(self, content):
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        message_data.get_targets.return_value = ["10.0.0.1"]
        message_data.target_results.ip_to_asset_id_map = {}
        message_data.inject_content = content
        message_data.raw_data = {"attachments": None}
        return message_data

    def test_authenticated_template_without_credentials_sends_nothing(
        self, _cl, _ch, m_helper, m_process, _parser, _dump
    ):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()
        with self.assertRaises(module.MissingTemplateInputs) as raised:
            injector.nuclei_execution(0, self._message({"template": self.template}))
        self.assertIn("missing credentials", str(raised.exception))
        m_process.nuclei_execute.assert_not_called()
        m_helper.return_value.api.inject.execution_callback.assert_not_called()

    def test_unknown_template_id_is_not_executed(
        self, _cl, _ch, m_helper, m_process, _parser, _dump
    ):
        m_helper.return_value.api = MagicMock()
        injector = module.OpenAEVNuclei()
        with self.assertRaises(module.TemplateNotFound) as raised:
            injector.nuclei_execution(
                0, self._message({"options": "-id CVE-2023-28434"})
            )
        self.assertEqual(raised.exception.missing, ["CVE-2023-28434"])
        m_process.nuclei_execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
