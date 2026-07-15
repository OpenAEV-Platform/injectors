import json
import os
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch

from ai_redteam.engines.garak import GarakEngine
from ai_redteam.engines.native import NativeEngine
from ai_redteam.engines.promptfoo import PromptfooEngine
from ai_redteam.engines.pyrit import PyritEngine
from ai_redteam.targets.llm_client import LLMResponse
from ai_redteam.targets.target_resolver import TargetConfig


def _target():
    return TargetConfig(
        provider="OPENAI_COMPATIBLE", endpoint="https://api.example.com"
    )


class NativeEngineTest(TestCase):
    @patch("ai_redteam.engines.native.llm_client.send_prompt")
    def test_reports_vulnerable_on_canary_leak(self, send_prompt):
        send_prompt.return_value = LLMResponse("OAEV_PWNED_m1", 200, {})
        content = {"attack_prompt": "do it {marker}"}
        result = NativeEngine().run(content, _target(), "m1", ctx={})
        self.assertTrue(result.success)
        self.assertEqual(result.status, "SUCCESS")
        self.assertIn("vulnerability", result.outputs)

    @patch("ai_redteam.engines.native.llm_client.send_prompt")
    def test_reports_defended_on_refusal(self, send_prompt):
        send_prompt.return_value = LLMResponse("I'm sorry, I can't.", 200, {})
        result = NativeEngine().run({"attack_prompt": "x"}, _target(), "m1", ctx={})
        self.assertFalse(result.success)
        self.assertEqual(result.status, "SUCCESS")

    @patch(
        "ai_redteam.engines.native.llm_client.send_prompt",
        side_effect=RuntimeError("down"),
    )
    def test_returns_error_status_on_exception(self, _send_prompt):
        result = NativeEngine().run({"attack_prompt": "x"}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")
        self.assertFalse(result.success)

    @patch("ai_redteam.engines.native.llm_client.send_prompt")
    def test_returns_error_status_on_http_error(self, send_prompt):
        send_prompt.return_value = LLMResponse('{"detail":"Not authenticated"}', 401, {})
        result = NativeEngine().run({"attack_prompt": "x"}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")
        self.assertFalse(result.success)
        self.assertNotIn("vulnerability", result.outputs)
        self.assertEqual(result.outputs["http_status"], 401)
        self.assertIn("HTTP 401", result.message)

    @patch("ai_redteam.engines.native.llm_client.send_prompt")
    def test_canary_leak_with_non_2xx_is_not_vulnerable(self, send_prompt):
        # Even if the body echoes the canary, a non-2xx must not be a vulnerability
        send_prompt.return_value = LLMResponse("OAEV_PWNED_m1", 500, {})
        result = NativeEngine().run({"attack_prompt": "x"}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")
        self.assertFalse(result.success)


class PyritEngineTest(TestCase):
    @patch("ai_redteam.engines.pyrit.llm_client.send_prompt")
    def test_succeeds_when_canary_leaks_mid_campaign(self, send_prompt):
        send_prompt.side_effect = [
            LLMResponse("nope", 200, {}),
            LLMResponse("here is OAEV_PWNED_m1", 200, {}),
        ]
        content = {"pyrit_objective": "leak {marker}", "pyrit_max_turns": "5"}
        result = PyritEngine().run(content, _target(), "m1", ctx={})
        self.assertTrue(result.success)

    @patch("ai_redteam.engines.pyrit.llm_client.send_prompt")
    def test_defended_when_all_turns_resist(self, send_prompt):
        send_prompt.return_value = LLMResponse("I will not.", 200, {})
        result = PyritEngine().run({"pyrit_objective": "o"}, _target(), "m1", ctx={})
        self.assertFalse(result.success)

    @patch(
        "ai_redteam.engines.pyrit.llm_client.send_prompt", side_effect=RuntimeError("x")
    )
    def test_error_on_exception(self, _send_prompt):
        result = PyritEngine().run({"pyrit_objective": "o"}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")


class GarakEngineTest(TestCase):
    @patch("ai_redteam.engines.garak.shutil.which", return_value=None)
    def test_error_when_garak_not_installed(self, _which):
        result = GarakEngine().run({}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")

    def test_parse_report_counts_eval_entries(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(
                json.dumps(
                    {"entry_type": "eval", "total": 5, "passed": 3, "probe": "p1"}
                )
                + "\n"
            )
            handle.write(
                json.dumps(
                    {"entry_type": "eval", "total": 2, "passed": 2, "probe": "p2"}
                )
                + "\n"
            )
            handle.write("\n")
            path = handle.name
        try:
            passed, total, failed = GarakEngine._parse_report(path)
            self.assertEqual((passed, total), (5, 7))
            self.assertEqual(failed, ["p1"])
        finally:
            os.unlink(path)

    def test_parse_report_missing_file(self):
        self.assertEqual(GarakEngine._parse_report("/does/not/exist.jsonl"), (0, 0, []))

    def test_run_reports_vulnerable_from_report(self):
        workdir = tempfile.mkdtemp(prefix="garak_test_")
        with open(
            os.path.join(workdir, "scan.report.jsonl"), "w", encoding="utf-8"
        ) as handle:
            handle.write(
                json.dumps(
                    {
                        "entry_type": "eval",
                        "total": 4,
                        "passed": 1,
                        "probe": "promptinject",
                    }
                )
                + "\n"
            )
        with patch(
            "ai_redteam.engines.garak.shutil.which", return_value="/usr/bin/garak"
        ), patch(
            "ai_redteam.engines.garak.tempfile.mkdtemp", return_value=workdir
        ), patch(
            "ai_redteam.engines.garak.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="garak output"),
        ):
            result = GarakEngine().run({}, _target(), "m1", ctx={})
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["garak_total"], 4)
        # workdir must be cleaned up by the finally block
        self.assertFalse(os.path.exists(workdir))


class PromptfooEngineTest(TestCase):
    @patch("ai_redteam.engines.promptfoo.shutil.which", return_value=None)
    def test_error_when_promptfoo_not_installed(self, _which):
        result = PromptfooEngine().run({}, _target(), "m1", ctx={})
        self.assertEqual(result.status, "ERROR")

    def test_parse_results_from_stats(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump({"results": {"stats": {"successes": 4, "failures": 1}}}, handle)
            path = handle.name
        try:
            self.assertEqual(PromptfooEngine._parse_results(path), (4, 1))
        finally:
            os.unlink(path)

    def test_parse_results_missing_file(self):
        self.assertEqual(PromptfooEngine._parse_results("/nope.json"), (0, 0))

    def test_run_reports_vulnerable_from_results(self):
        workdir = tempfile.mkdtemp(prefix="promptfoo_test_")
        with open(
            os.path.join(workdir, "results.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump({"results": {"stats": {"successes": 2, "failures": 3}}}, handle)
        with patch(
            "ai_redteam.engines.promptfoo.shutil.which",
            return_value="/usr/bin/promptfoo",
        ), patch(
            "ai_redteam.engines.promptfoo.tempfile.mkdtemp", return_value=workdir
        ), patch(
            "ai_redteam.engines.promptfoo.subprocess.run",
            return_value=MagicMock(returncode=0, stdout="promptfoo output"),
        ):
            result = PromptfooEngine().run({}, _target(), "m1", ctx={})
        self.assertTrue(result.success)
        self.assertEqual(result.outputs["promptfoo_failures"], 3)
        self.assertFalse(os.path.exists(workdir))
