from unittest import TestCase
from unittest.mock import MagicMock

from injector_common.traces import send_per_target_traces


class SendPerTargetTracesTest(TestCase):
    def setUp(self):
        self.helper = MagicMock()
        self.helper.api = MagicMock()
        self.helper.injector_logger = MagicMock()

    def test_emits_one_trace_per_asset_backed_target(self):
        send_per_target_traces(
            self.helper,
            "inject-1",
            {"10.0.0.1": "asset-1", "10.0.0.2": "asset-2"},
            label="nmap scan",
            start=0.0,
        )

        calls = self.helper.api.inject.execution_callback.call_args_list
        self.assertEqual(len(calls), 2)
        identifiers = sorted(
            c.kwargs["data"]["execution_context_identifiers"][0] for c in calls
        )
        self.assertEqual(identifiers, ["asset-1", "asset-2"])
        for c in calls:
            data = c.kwargs["data"]
            self.assertEqual(c.kwargs["inject_id"], "inject-1")
            self.assertEqual(data["execution_action"], "command_execution")
            self.assertEqual(data["execution_status"], "INFO")
            self.assertIn(
                "nmap scan executed against target", data["execution_message"]
            )

    def test_skips_targets_without_asset_id(self):
        send_per_target_traces(
            self.helper,
            "inject-1",
            {"10.0.0.1": "asset-1", "manual-host": None},
            label="nuclei scan",
            start=0.0,
        )

        calls = self.helper.api.inject.execution_callback.call_args_list
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0].kwargs["data"]["execution_context_identifiers"], ["asset-1"]
        )

    def test_noop_when_map_is_empty_or_none(self):
        send_per_target_traces(
            self.helper, "inject-1", {}, label="nmap scan", start=0.0
        )
        send_per_target_traces(
            self.helper, "inject-1", None, label="nmap scan", start=0.0
        )
        self.helper.api.inject.execution_callback.assert_not_called()

    def test_one_target_failure_does_not_stop_the_others(self):
        # A callback failure for one target must be logged but must not prevent
        # the remaining targets from getting their trace.
        self.helper.api.inject.execution_callback.side_effect = [
            RuntimeError("boom"),
            None,
        ]

        send_per_target_traces(
            self.helper,
            "inject-1",
            {"10.0.0.1": "asset-1", "10.0.0.2": "asset-2"},
            label="NetExec",
            start=0.0,
        )

        self.assertEqual(self.helper.api.inject.execution_callback.call_count, 2)
        self.helper.injector_logger.error.assert_called_once()
