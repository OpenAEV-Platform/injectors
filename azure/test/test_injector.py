import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import azure_injector.openaev_azure as mod
from azure_injector.contracts_azure import AZURE_DETONATE_CONTRACT

from injector_common.stratus_executor import StratusExecutor, StratusResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "azure--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVAzure()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {
                "injector_contract_id": AZURE_DETONATE_CONTRACT
            },
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success_reports_success(self):
        injector = make_injector()
        injector.stratus = MagicMock()
        injector.stratus.detonate.return_value = StratusResult(
            success=True,
            technique_id="t",
            status="DETONATED",
            message="done",
            outputs={"technique": ["t"]},
        )
        injector.process_message(
            _data(
                {
                    "technique_id": ["azure.execution.vm-run-command"],
                    "azure_tenant_id": "t",
                    "azure_subscription_id": "s",
                    "azure_client_id": "c",
                    "azure_client_secret": "x",
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_missing_technique_reports_error(self):
        injector = make_injector()
        injector.stratus = MagicMock()
        injector.process_message(_data({}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class StratusExecutorTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = StratusExecutor().detonate("azure.foo", env={"A": "B"})
        self.assertTrue(result.success)
        self.assertEqual(result.status, "DETONATED")

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        result = StratusExecutor().detonate("azure.foo", cleanup=False)
        self.assertFalse(result.success)
        self.assertIn("boom", result.message)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_detonate_missing_binary(self, _run):
        result = StratusExecutor().detonate("azure.foo")
        self.assertFalse(result.success)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = StratusExecutor().cleanup("azure.foo")
        self.assertTrue(result.success)
