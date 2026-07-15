import os
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

import webapp_injector.openaev_webapp as mod
from webapp_injector.contracts_webapp import SQLMAP_CONTRACT, ZAP_BASELINE_CONTRACT
from webapp_injector.helpers.webapp_executor import WebappExecutor, WebappResult

BASE_ENV = {
    "OPENAEV_URL": "http://localhost:3001",
    "OPENAEV_TOKEN": "token",
    "INJECTOR_ID": "webapp--test",
}


def make_injector():
    with patch.dict(os.environ, BASE_ENV, clear=False), patch.object(
        mod, "OpenAEVInjectorHelper"
    ), patch.object(mod, "OpenAEVConfigHelper"), patch.object(
        mod, "intercept_dump_argument"
    ), patch.object(
        mod, "open", mock_open(read_data=b"icon"), create=True
    ):
        injector = mod.OpenAEVWebapp()
    injector.helper = MagicMock()
    return injector


def _data(contract_id, content):
    return {
        "injection": {
            "inject_id": "i1",
            "inject_injector_contract": {"injector_contract_id": contract_id},
            "inject_content": content,
        }
    }


class ProcessMessageTest(TestCase):
    def _callback(self, injector):
        return injector.helper.api.inject.execution_callback.call_args.kwargs["data"]

    def test_zap_dispatch(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.run_zap_baseline.return_value = WebappResult(True, "ok")
        injector.process_message(
            _data(ZAP_BASELINE_CONTRACT, {"target_url": "http://t"})
        )
        injector.executor.run_zap_baseline.assert_called_once()

    def test_sqlmap_dispatch(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.executor.run_sqlmap.return_value = WebappResult(True, "ok")
        injector.process_message(_data(SQLMAP_CONTRACT, {"target_url": "http://t"}))
        injector.executor.run_sqlmap.assert_called_once()

    def test_missing_url_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data(ZAP_BASELINE_CONTRACT, {}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_unknown_contract_reports_error(self):
        injector = make_injector()
        injector.executor = MagicMock()
        injector.process_message(_data("nope", {"target_url": "http://t"}))
        self.assertEqual(self._callback(injector)["execution_status"], "ERROR")

    def test_start_listens(self):
        injector = make_injector()
        injector.start()
        injector.helper.listen.assert_called_once()


class ExecutorTest(TestCase):
    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_sqlmap_success(self, run):
        run.return_value = MagicMock(
            returncode=0, stdout="Parameter: id (GET)\n", stderr=""
        )
        result = WebappExecutor().run_sqlmap("http://t")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["vulnerabilities"], ["Parameter: id (GET)"])

    @patch(
        "webapp_injector.helpers.webapp_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_run_sqlmap_missing_binary(self, _run):
        self.assertFalse(WebappExecutor().run_sqlmap("http://t").success)

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_sqlmap_non_zero_exit_is_error(self, run):
        run.return_value = MagicMock(
            returncode=1, stdout="", stderr="connection refused"
        )
        result = WebappExecutor().run_sqlmap("http://t")
        self.assertFalse(result.success)
        self.assertIn("connection refused", result.message)

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_sqlmap_message_redacts_url_credentials(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        result = WebappExecutor().run_sqlmap(
            "http://user:pass@example.com/app?token=secret"
        )
        self.assertFalse(result.success)
        self.assertNotIn("pass", result.message)
        self.assertNotIn("secret", result.message)
        self.assertIn("***@example.com", result.message)

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_zap_no_report(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # ZAP is mocked so no report file is produced.
        self.assertFalse(WebappExecutor().run_zap_baseline("http://t").success)

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_zap_message_redacts_url_credentials(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # ZAP is mocked so no report file is produced -> error message path.
        result = WebappExecutor().run_zap_baseline(
            "http://user:pass@example.com/app?token=secret"
        )
        self.assertFalse(result.success)
        self.assertNotIn("pass", result.message)
        self.assertNotIn("secret", result.message)
        self.assertIn("***@example.com", result.message)

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_zap_invalid_report_is_error(self, run):
        def _write_invalid_report(cmd, **kwargs):
            report_path = cmd[cmd.index("-J") + 1]
            with open(report_path, "w", encoding="utf-8") as report_file:
                report_file.write("not json")
            return MagicMock(returncode=0, stdout="", stderr="")

        run.side_effect = _write_invalid_report
        result = WebappExecutor().run_zap_baseline("http://t")
        self.assertFalse(result.success)
        self.assertIn("invalid", result.message.lower())

    @patch("webapp_injector.helpers.webapp_executor.subprocess.run")
    def test_run_zap_success_parses_report(self, run):
        def _write_report(cmd, **kwargs):
            report_path = cmd[cmd.index("-J") + 1]
            with open(report_path, "w", encoding="utf-8") as report_file:
                report_file.write('{"site": [{"alerts": [{"alert": "XSS"}]}]}')
            return MagicMock(returncode=0, stdout="", stderr="")

        run.side_effect = _write_report
        result = WebappExecutor().run_zap_baseline("http://t")
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["vulnerabilities"], ["XSS"])

    @patch(
        "webapp_injector.helpers.webapp_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_run_zap_missing_binary(self, _run):
        self.assertFalse(WebappExecutor().run_zap_baseline("http://t").success)
