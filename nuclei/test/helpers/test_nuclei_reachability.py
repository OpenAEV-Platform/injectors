import json
from unittest import TestCase
from unittest.mock import MagicMock

from nuclei.helpers.nuclei_reachability import (
    NO_RESPONSE_REASON,
    assess_reachability,
    normalize_host,
    send_reachability_traces,
    unreached_summary,
)


def _event(host, matched, error=None, **extra):
    event = {"template-id": "CVE-2023-28432", "host": host, "matcher-status": matched}
    if error:
        event["error"] = error
    event.update(extra)
    return json.dumps(event)


class NormalizeHostTest(TestCase):
    def test_strips_scheme_port_path_and_case(self):
        self.assertEqual(normalize_host("https://Example.com:8443/x"), "example.com")
        self.assertEqual(normalize_host("example.com:80"), "example.com")
        self.assertEqual(normalize_host("10.0.0.1"), "10.0.0.1")
        self.assertEqual(normalize_host(""), "")
        self.assertEqual(normalize_host(None), "")


class AssessReachabilityTest(TestCase):
    def test_response_without_match_is_reached(self):
        stdout = _event("http://10.0.0.1:80", False)
        self.assertEqual(
            assess_reachability(stdout, "", ["10.0.0.1"]), {"10.0.0.1": None}
        )

    def test_match_is_reached(self):
        stdout = _event("https://example.com", True, info={"severity": "high"})
        self.assertEqual(
            assess_reachability(stdout, "", ["example.com"]), {"example.com": None}
        )

    def test_request_error_is_not_reached_with_its_reason(self):
        stdout = _event(
            "http://unknown.invalid",
            False,
            error="no address found for host",
        )
        verdicts = assess_reachability(stdout, "", ["unknown.invalid"])
        self.assertEqual(verdicts["unknown.invalid"], "no address found for host")

    def test_one_successful_request_wins_over_errors(self):
        stdout = "\n".join(
            [
                _event("http://10.0.0.1:8080", False, error="connection refused"),
                _event("http://10.0.0.1:80", False),
            ]
        )
        self.assertEqual(
            assess_reachability(stdout, "", ["10.0.0.1"]), {"10.0.0.1": None}
        )

    def test_max_host_error_skip_on_stderr(self):
        stderr = (
            "[INF] Templates loaded for current scan: 1\n"
            "\x1b[33m[WRN]\x1b[0m [CVE-2023-28432] Skipped 10.0.0.9:443 from target "
            "list as found unresponsive 30 times\n"
        )
        verdicts = assess_reachability("", stderr, ["10.0.0.9"])
        self.assertTrue(verdicts["10.0.0.9"].startswith("found unresponsive 30 times"))

    def test_no_event_at_all_is_not_reached(self):
        # Today's main scores this case "Not vulnerable": Nuclei exits 0 and writes
        # nothing for a host it never reached.
        verdicts = assess_reachability("", "", ["host.example"])
        self.assertEqual(verdicts["host.example"], NO_RESPONSE_REASON)

    def test_mixed_batch_gets_one_verdict_per_target(self):
        stdout = "\n".join(
            [
                "not json",
                _event("http://10.0.0.1", False),
                _event("http://down.example", False, error="i/o timeout"),
            ]
        )
        verdicts = assess_reachability(
            stdout, "", ["10.0.0.1", "down.example", "10.0.0.3"]
        )
        self.assertIsNone(verdicts["10.0.0.1"])
        self.assertEqual(verdicts["down.example"], "i/o timeout")
        self.assertEqual(verdicts["10.0.0.3"], NO_RESPONSE_REASON)

    def test_summary_lists_unreached_targets(self):
        text = unreached_summary({"a.example": "i/o timeout"}, 3)
        self.assertEqual(text, "1/3 target(s) not reached\n- a.example: i/o timeout")


class SendReachabilityTracesTest(TestCase):
    def test_traces_carry_the_real_outcome_per_asset(self):
        helper = MagicMock()
        send_reachability_traces(
            helper,
            "inject-1",
            {"10.0.0.1": None, "10.0.0.2": "connection refused", "10.0.0.3": None},
            {"10.0.0.1": "asset-1", "10.0.0.2": "asset-2"},
            start=0.0,
        )
        calls = helper.api.inject.execution_callback.call_args_list
        self.assertEqual(len(calls), 2)
        by_asset = {
            c.kwargs["data"]["execution_context_identifiers"][0]: c.kwargs["data"]
            for c in calls
        }
        self.assertEqual(by_asset["asset-1"]["execution_status"], "EXECUTED")
        self.assertEqual(by_asset["asset-2"]["execution_status"], "ERROR")
        self.assertIn(
            "not reached: connection refused", by_asset["asset-2"]["execution_message"]
        )
        for data in by_asset.values():
            self.assertEqual(data["execution_action"], "command_execution")

    def test_noop_without_asset_map(self):
        helper = MagicMock()
        send_reachability_traces(helper, "inject-1", {"10.0.0.1": None}, {}, 0.0)
        helper.api.inject.execution_callback.assert_not_called()
