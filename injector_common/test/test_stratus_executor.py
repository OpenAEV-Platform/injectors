import subprocess
from unittest import TestCase
from unittest.mock import MagicMock, patch

from injector_common.stratus_executor import StratusExecutor, StratusResult


class StratusExecutorTest(TestCase):
    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = StratusExecutor().detonate("azure.foo")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "DETONATED")
        self.assertEqual(result.outputs, {"technique": ["azure.foo"]})

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_appends_cleanup_flag(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        StratusExecutor().detonate("azure.foo", cleanup=True)
        self.assertIn("--cleanup", run.call_args.args[0])

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_without_cleanup_flag(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        StratusExecutor().detonate("azure.foo", cleanup=False)
        self.assertNotIn("--cleanup", run.call_args.args[0])

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure_uses_stderr(self, run):
        run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        result = StratusExecutor().detonate("azure.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")
        self.assertIn("boom", result.message)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_detonate_failure_falls_back_to_stdout(self, run):
        run.return_value = MagicMock(returncode=1, stdout="stdout detail", stderr="")
        result = StratusExecutor().detonate("azure.foo")
        self.assertFalse(result.success)
        self.assertIn("stdout detail", result.message)

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="stratus", timeout=1),
    )
    def test_detonate_timeout(self, _run):
        result = StratusExecutor().detonate("azure.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "TIMEOUT")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_detonate_missing_binary(self, _run):
        result = StratusExecutor().detonate("azure.foo")
        self.assertFalse(result.success)
        self.assertIn("not found", result.message)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_run_filters_none_env_values(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        StratusExecutor().detonate("azure.foo", env={"KEEP": "value", "DROP": None})
        passed_env = run.call_args.kwargs["env"]
        self.assertEqual(passed_env["KEEP"], "value")
        self.assertNotIn("DROP", passed_env)

    @patch("injector_common.stratus_executor.subprocess.run")
    def test_cleanup_success(self, run):
        run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = StratusExecutor().cleanup("azure.foo")
        self.assertTrue(result.success)
        self.assertEqual(result.status, "CLEAN")

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=FileNotFoundError(),
    )
    def test_cleanup_missing_binary_has_friendly_message(self, _run):
        result = StratusExecutor().cleanup("azure.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "ERROR")
        self.assertEqual(
            result.message, "stratus binary not found in the injector image"
        )

    @patch(
        "injector_common.stratus_executor.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="stratus", timeout=1),
    )
    def test_cleanup_timeout(self, _run):
        result = StratusExecutor().cleanup("azure.foo")
        self.assertFalse(result.success)
        self.assertEqual(result.status, "TIMEOUT")

    def test_result_is_stratus_result(self):
        with patch("injector_common.stratus_executor.subprocess.run") as run:
            run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            self.assertIsInstance(
                StratusExecutor().detonate("azure.foo"), StratusResult
            )
