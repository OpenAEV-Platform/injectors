import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import gcp_injector.openaev_gcp as mod
from gcp_injector.contracts_gcp import GCP_DETONATE_CONTRACT

from injector_common.stratus_executor import StratusExecutor, StratusResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "gcp--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVGcp()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": GCP_DETONATE_CONTRACT},
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success_writes_key_and_detonates(self):
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
                    "technique_id": ["gcp.exfiltration.share-compute-disk"],
                    "gcp_project_id": "proj",
                    "gcp_service_account_key": '{"type": "service_account"}',
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_missing_key_reports_error(self):
        injector = make_injector()
        injector.stratus = MagicMock()
        injector.process_message(
            _data({"technique_id": ["gcp.exfiltration.share-compute-disk"]})
        )
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class StratusExecutorTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = StratusExecutor().detonate("gcp.foo", env={"A": "B"})
        self.assertTrue(result.success)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        result = StratusExecutor().detonate("gcp.foo", cleanup=False)
        self.assertFalse(result.success)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_detonate_missing_binary(self, _run):
        self.assertFalse(StratusExecutor().detonate("gcp.foo").success)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        self.assertTrue(StratusExecutor().cleanup("gcp.foo").success)
