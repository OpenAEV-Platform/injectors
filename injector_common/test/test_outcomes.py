from unittest import TestCase
from unittest.mock import MagicMock

from injector_common.inject_gone import InjectGoneError
from injector_common.outcomes import (
    HOST_DOWN,
    HOST_UP,
    MAX_STDERR_LENGTH,
    MAX_TRACE_MESSAGE_LENGTH,
    NOT_SCANNED,
    TargetOutcome,
    build_global_message,
    send_scan_progress_trace,
    send_target_outcome_traces,
    summarize_outcomes,
)
from injector_common.targets import TargetResolution


class _NotFound(Exception):
    response_code = 404


def _outcomes():
    return [
        TargetOutcome(TargetResolution("10.0.0.1", "a1", "web-01"), HOST_UP, 3),
        TargetOutcome(TargetResolution("10.0.0.2", "a2", "db-02"), HOST_DOWN),
        TargetOutcome(
            TargetResolution("x.invalid", "a3"),
            NOT_SCANNED,
            reason="hostname did not resolve",
        ),
        TargetOutcome(TargetResolution("192.0.2.9"), HOST_UP, 0),
    ]


class TargetOutcomeTest(TestCase):
    def test_status_and_message(self):
        self.assertEqual(
            [(o.status, o.describe()) for o in _outcomes()],
            [
                ("EXECUTED", "10.0.0.1 (asset web-01): host up, 3 open ports"),
                ("WARNING", "10.0.0.2 (asset db-02): host down or no response"),
                (
                    "WARNING",
                    "x.invalid (asset a3): not scanned, hostname did not resolve",
                ),
                ("EXECUTED", "192.0.2.9: host up, no open port"),
            ],
        )

    def test_message_is_capped(self):
        outcome = TargetOutcome(TargetResolution("h" * 500, "a1"), HOST_DOWN)
        self.assertEqual(len(outcome.describe()), MAX_TRACE_MESSAGE_LENGTH)
        self.assertTrue(outcome.describe().endswith("..."))


class SummaryTest(TestCase):
    def test_partial_run_is_warning_with_counts(self):
        outcomes = _outcomes()
        summary = summarize_outcomes(outcomes, open_ports=3)
        self.assertEqual(summary.status, "WARNING")
        message = build_global_message(summary, outcomes)
        lines = message.split("\n")
        self.assertEqual(lines[0], "3/4 targets scanned, 2 up, 2 missed, 3 open ports")
        self.assertEqual(len(lines), 3)

    def test_full_run_is_executed(self):
        outcomes = [_outcomes()[0], _outcomes()[3]]
        summary = summarize_outcomes(outcomes, open_ports=3)
        self.assertEqual(summary.status, "EXECUTED")
        self.assertEqual(
            build_global_message(summary, outcomes),
            "2/2 targets scanned, 2 up, 0 missed, 3 open ports",
        )

    def test_non_zero_exit_is_warning(self):
        summary = summarize_outcomes([_outcomes()[0]], 3, exit_code=2, tool="nmap")
        self.assertEqual(summary.status, "WARNING")
        self.assertIn("(nmap exited with code 2, results kept)", summary.headline())

    def test_non_zero_exit_with_partial_results_is_warning_with_stderr(self):
        outcomes = [_outcomes()[0], _outcomes()[2]]
        summary = summarize_outcomes(
            outcomes, 3, exit_code=1, tool="nmap", stderr=b"  some warning\n"
        )
        self.assertEqual(summary.status, "WARNING")
        message = build_global_message(summary, outcomes)
        self.assertIn("(nmap exited with code 1, results kept)", message)
        self.assertTrue(message.endswith("nmap stderr:\nsome warning"))

    def test_non_zero_exit_with_nothing_scanned_is_error_with_stderr(self):
        outcomes = [_outcomes()[2]]
        stderr = b"NSE: failed to initialize the script engine\n"
        summary = summarize_outcomes(
            outcomes, 0, exit_code=1, tool="nmap", stderr=stderr
        )
        self.assertEqual(summary.status, "ERROR")
        message = build_global_message(summary, outcomes)
        self.assertTrue(
            message.startswith(
                "0/1 targets scanned, 0 up, 1 missed, 0 open ports "
                "(nmap exited with code 1, no target scanned)"
            )
        )
        self.assertIn(
            "nmap stderr:\nNSE: failed to initialize the script engine", message
        )

    def test_non_zero_exit_with_no_target_at_all_is_error(self):
        summary = summarize_outcomes([], 0, exit_code=1, tool="nmap")
        self.assertEqual(summary.status, "ERROR")

    def test_zero_exit_drops_stderr_and_keeps_status(self):
        outcomes = [_outcomes()[2]]
        summary = summarize_outcomes(outcomes, 0, stderr=b"progress noise")
        self.assertEqual(summary.status, "WARNING")
        self.assertNotIn("stderr", build_global_message(summary, outcomes))

    def test_stderr_is_capped(self):
        summary = summarize_outcomes(
            [_outcomes()[0]], 3, exit_code=1, tool="nmap", stderr="e" * 5000
        )
        self.assertEqual(len(summary.stderr), MAX_STDERR_LENGTH)
        self.assertTrue(summary.stderr.endswith("..."))


class SendTracesTest(TestCase):
    def setUp(self):
        self.helper = MagicMock()

    def test_one_trace_per_asset_target_and_unscanned_manual_target(self):
        outcomes = _outcomes() + [
            TargetOutcome(
                TargetResolution("y.invalid"),
                NOT_SCANNED,
                reason="hostname did not resolve",
            )
        ]
        send_target_outcome_traces(self.helper, "inject-1", outcomes, 0.0)

        calls = self.helper.api.inject.execution_callback.call_args_list
        sent = [
            (
                c.kwargs["data"].get("execution_context_identifiers"),
                c.kwargs["data"]["execution_status"],
            )
            for c in calls
        ]
        # The manual target that answered is only in the global counts.
        self.assertEqual(
            sent,
            [
                (["a1"], "EXECUTED"),
                (["a2"], "WARNING"),
                (["a3"], "WARNING"),
                (None, "WARNING"),
            ],
        )
        for c in calls:
            self.assertEqual(c.kwargs["data"]["execution_action"], "command_execution")

    def test_callback_failure_does_not_stop_the_others(self):
        self.helper.api.inject.execution_callback.side_effect = [
            RuntimeError("boom"),
            None,
            None,
        ]
        send_target_outcome_traces(self.helper, "inject-1", _outcomes()[:3], 0.0)
        self.assertEqual(self.helper.api.inject.execution_callback.call_count, 3)
        self.helper.injector_logger.error.assert_called_once()

    def test_outcome_trace_404_stops_with_inject_gone(self):
        self.helper.api.inject.execution_callback.side_effect = [_NotFound()]
        with self.assertRaises(InjectGoneError):
            send_target_outcome_traces(self.helper, "inject-1", _outcomes()[:3], 0.0)
        self.assertEqual(self.helper.api.inject.execution_callback.call_count, 1)
        self.helper.injector_logger.error.assert_not_called()

    def test_progress_trace_404_raises_inject_gone(self):
        self.helper.api.inject.execution_callback.side_effect = _NotFound()
        with self.assertRaises(InjectGoneError):
            send_scan_progress_trace(
                self.helper, "inject-1", 3, label="nmap scan", start=0
            )
        self.helper.injector_logger.error.assert_not_called()

    def test_progress_trace(self):
        send_scan_progress_trace(
            self.helper, "inject-1", 120, label="nmap scan", start=0
        )
        data = self.helper.api.inject.execution_callback.call_args.kwargs["data"]
        self.assertEqual(data["execution_status"], "INFO")
        self.assertIn("120 target(s)", data["execution_message"])
        self.assertIn("inject.execution.threshold.minutes", data["execution_message"])

    def test_progress_trace_states_no_threshold_value(self):
        # The platform setting may differ from its default: the trace never
        # claims a value the injector cannot read.
        send_scan_progress_trace(
            self.helper, "inject-1", 120, label="nmap scan", start=0
        )
        message = self.helper.api.inject.execution_callback.call_args.kwargs["data"][
            "execution_message"
        ]
        self.assertNotIn("default", message)
        self.assertNotRegex(message, r"\(\s*\d+\s*\)")
        self.assertIn("timeout trace states the minutes applied", message)

    def test_no_progress_trace_without_targets(self):
        send_scan_progress_trace(self.helper, "inject-1", 0, label="nmap scan", start=0)
        self.helper.api.inject.execution_callback.assert_not_called()
