import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import kubernetes_injector.openaev_kubernetes as mod
from kubernetes_injector.contracts_kubernetes import K8S_DETONATE_CONTRACT

from injector_common.stratus_executor import StratusExecutor, StratusResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "kubernetes--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVKubernetes()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": K8S_DETONATE_CONTRACT},
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success_writes_kubeconfig_and_detonates(self):
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
                    "technique_id": ["k8s.credential-access.dump-secrets"],
                    "kubeconfig": "apiVersion: v1",
                }
            )
        )
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_missing_kubeconfig_reports_error(self):
        injector = make_injector()
        injector.stratus = MagicMock()
        injector.process_message(
            _data({"technique_id": ["k8s.credential-access.dump-secrets"]})
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
        self.assertTrue(StratusExecutor().detonate("k8s.foo", env={"A": "B"}).success)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        self.assertFalse(StratusExecutor().detonate("k8s.foo", cleanup=False).success)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_detonate_missing_binary(self, _run):
        self.assertFalse(StratusExecutor().detonate("k8s.foo").success)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        self.assertTrue(StratusExecutor().cleanup("k8s.foo").success)
