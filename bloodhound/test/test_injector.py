import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import bloodhound_injector.openaev_bloodhound as mod
from bloodhound_injector.contracts_bloodhound import AD_COLLECTION_CONTRACT
from bloodhound_injector.helpers.bloodhound_executor import (
    BloodhoundExecutor,
    BloodhoundResult,
)

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "bloodhound--test",
}

CONTENT = {
    "domain": "corp.local",
    "username": "user",
    "password": "secret",
    "domain_controller": "dc01.corp.local",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVBloodhound()
    injector.helper = MagicMock()
    return injector


def _data(content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {
                "injector_contract_id": AD_COLLECTION_CONTRACT
            },
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_success(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.run_collection.return_value = BloodhoundResult(
            True, "collected", {"users": ["a"]}
        )
        injector.process_message(_data(CONTENT))
        self.assertEqual(self._callback(injector)["execution_status"], "SUCCESS")

    def test_missing_field_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data({"domain": "corp.local"}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")
        injector.executor.run_collection.assert_not_called()

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class ExecutorTest(TestCase):
    @patch("bloodhound_injector.helpers.bloodhound_executor.subprocess.run")
    def test_run_collection_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        executor = BloodhoundExecutor(logger=MagicMock())
        result = executor.run_collection(
            "corp.local", "user", "secret", "dc01.corp.local"
        )
        self.assertTrue(result.success)
        run.assert_called_once()

    @patch(
        "bloodhound_injector.helpers.bloodhound_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_run_collection_missing_binary(self, _run):
        result = BloodhoundExecutor().run_collection(
            "corp.local", "user", "secret", "dc01.corp.local"
        )
        self.assertFalse(result.success)
