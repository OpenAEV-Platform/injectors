"""Scan time limit of the scanning injectors: threshold read, source, start trace
(OpenAEV-Platform/injectors#575)."""

import unittest
from unittest.mock import MagicMock

from pyoaev.client import OpenAEV

from injector_common.scan_budget import (
    DEFAULT_SCAN_TIMEOUT,
    SCAN_TIMEOUT_FIELD,
    THRESHOLD_SETTING_KEY,
    platform_threshold_seconds,
    resolve_scan_timeout,
    send_scan_time_limit_trace,
)

VARIABLE = "NMAP_SCAN_TIMEOUT"


def _settings(minutes):
    return {
        "runtime_settings": [
            {"key": "agent_max_simultaneous_jobs", "value": "5"},
            {"key": THRESHOLD_SETTING_KEY, "value": str(minutes)},
        ]
    }


def _helper(settings=None, tenant_id=None):
    """A helper whose api is a real pyoaev client (URL building included) with
    http_request stubbed: the URL the injector asks for is the URL sent."""
    helper = MagicMock()
    helper.injector_logger = MagicMock()
    api = OpenAEV(url="https://openaev.test", token="t", tenant_id=tenant_id)
    response = MagicMock()
    response.headers = {"Content-Type": "application/json"}
    if isinstance(settings, Exception):
        api.http_request = MagicMock(side_effect=settings)
    else:
        response.json.return_value = settings if settings is not None else {}
        api.http_request = MagicMock(return_value=response)
    api.inject = MagicMock()
    helper.api = api
    return helper


def _start_trace(helper, limit):
    send_scan_time_limit_trace(helper, "inject-id", limit, VARIABLE, start=0)
    helper.api.inject.execution_callback.assert_called_once()
    return helper.api.inject.execution_callback.call_args.kwargs["data"]


class TestThresholdRead(unittest.TestCase):
    def test_tenant_injector_reads_the_platform_route(self):
        # Acceptance: tenant_id set + threshold 120 min -> 7140 s.
        helper = _helper(_settings(120), tenant_id="7a3c1f2e-tenant")
        limit = resolve_scan_timeout(helper, {}, None, VARIABLE)
        self.assertEqual(limit.seconds, 7140)
        url = helper.api.http_request.call_args.args[1]
        self.assertEqual(url, "https://openaev.test/api/settings")
        self.assertNotIn("/tenants/", url)

    def test_no_tenant_reads_the_same_route(self):
        helper = _helper(_settings(10))
        self.assertEqual(platform_threshold_seconds(helper), 600)
        url = helper.api.http_request.call_args.args[1]
        self.assertEqual(url, "https://openaev.test/api/settings")

    def test_threshold_is_cached(self):
        helper = _helper(_settings(30))
        for _ in range(3):
            self.assertEqual(resolve_scan_timeout(helper, {}, None).seconds, 1740)
        self.assertEqual(helper.api.http_request.call_count, 1)

    def test_failed_read_is_not_cached(self):
        helper = _helper(RuntimeError("503"))
        resolve_scan_timeout(helper, {}, None)
        resolve_scan_timeout(helper, {}, None)
        self.assertEqual(helper.api.http_request.call_count, 2)


class TestSourceAndStartTrace(unittest.TestCase):
    def test_inject_field(self):
        helper = _helper(_settings(120))
        limit = resolve_scan_timeout(
            helper, {SCAN_TIMEOUT_FIELD: "3600"}, 900, VARIABLE
        )
        self.assertEqual(limit.seconds, 3600)
        data = _start_trace(helper, limit)
        self.assertEqual(data["execution_status"], "INFO")
        self.assertEqual(data["execution_action"], "command_execution")
        self.assertEqual(
            data["execution_message"],
            "scan time limit: 3600 s (source: inject field scan_timeout_seconds)",
        )

    def test_deployment_variable(self):
        helper = _helper(_settings(120))
        limit = resolve_scan_timeout(helper, {}, "900", VARIABLE)
        self.assertEqual(limit.seconds, 900)
        data = _start_trace(helper, limit)
        self.assertEqual(data["execution_status"], "INFO")
        self.assertEqual(
            data["execution_message"],
            "scan time limit: 900 s (source: deployment variable NMAP_SCAN_TIMEOUT)",
        )

    def test_platform_threshold(self):
        helper = _helper(_settings(120))
        limit = resolve_scan_timeout(helper, {}, None, VARIABLE)
        data = _start_trace(helper, limit)
        self.assertEqual(data["execution_status"], "INFO")
        self.assertEqual(
            data["execution_message"],
            "scan time limit: 7140 s (source: platform inject execution threshold "
            "(120 min) minus 60 s)",
        )

    def test_platform_cap(self):
        helper = _helper(_settings(15))
        limit = resolve_scan_timeout(
            helper, {SCAN_TIMEOUT_FIELD: "7200"}, None, VARIABLE
        )
        self.assertEqual(limit.seconds, 840)
        data = _start_trace(helper, limit)
        self.assertEqual(data["execution_status"], "INFO")
        self.assertEqual(
            data["execution_message"],
            "scan time limit: 840 s (source: platform cap: 7200 s from the inject "
            "field scan_timeout_seconds capped below the platform inject execution "
            "threshold (15 min))",
        )

    def test_fallback_when_the_read_raises(self):
        # Acceptance: http_get raising -> fallback, a trace naming the fallback and
        # the two ways to raise it, and one ERROR log line.
        helper = _helper(RuntimeError("404 Not Found"), tenant_id="t-1")
        limit = resolve_scan_timeout(helper, {}, None, VARIABLE)
        self.assertEqual(limit.seconds, DEFAULT_SCAN_TIMEOUT)
        self.assertTrue(limit.fallback)
        data = _start_trace(helper, limit)
        self.assertEqual(data["execution_status"], "INFO")
        message = data["execution_message"]
        self.assertTrue(message.startswith("Warning: scan time limit: 540 s"))
        self.assertIn("fallback", message)
        self.assertIn("404 Not Found", message)
        self.assertIn("inject field 'scan_timeout_seconds'", message)
        self.assertIn("NMAP_SCAN_TIMEOUT key of the injector deployment", message)
        helper.injector_logger.error.assert_called_once()
        self.assertIn(
            "NMAP_SCAN_TIMEOUT", helper.injector_logger.error.call_args.args[0]
        )

    def test_fallback_is_logged_at_error_once(self):
        helper = _helper(RuntimeError("404"))
        for _ in range(3):
            resolve_scan_timeout(helper, {}, None, VARIABLE)
        helper.injector_logger.error.assert_called_once()

    def test_fallback_when_the_setting_is_missing(self):
        helper = _helper({"runtime_settings": []})
        limit = resolve_scan_timeout(helper, {}, None, VARIABLE)
        self.assertTrue(limit.fallback)
        self.assertIn(THRESHOLD_SETTING_KEY, limit.threshold_error)

    def test_requested_limit_kept_when_the_threshold_is_unreadable(self):
        helper = _helper(RuntimeError("404"))
        limit = resolve_scan_timeout(helper, {SCAN_TIMEOUT_FIELD: 3600}, None, VARIABLE)
        self.assertEqual(limit.seconds, 3600)
        self.assertFalse(limit.fallback)
        helper.injector_logger.error.assert_not_called()


if __name__ == "__main__":
    unittest.main()
