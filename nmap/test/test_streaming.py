"""Per-host reporting while nmap runs and retry of the result callbacks (#571)."""

import subprocess
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
from pyoaev.exceptions import OpenAEVUpdateError

import nmap.openaev_nmap as module
from injector_common.outcomes import HOST_DOWN, HOST_UP, NOT_SCANNED, WARNING
from injector_common.targets import Targets
from nmap.configuration.nmap_configs import ConfigLoaderNmap
from nmap.contracts.nmap_constants import TCP_SYN_SCAN_CONTRACT
from nmap.helpers.nmap_output_parser import TIME_LIMIT_REASON, NmapOutputParser
from nmap.helpers.nmap_stream_runner import run_nmap, split_hosts

_HEADER = '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap">'


def _host(ip, port_state="open"):
    return (
        f'<host><status state="up" reason="syn-ack"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><hostnames/><ports>'
        f'<port protocol="tcp" portid="22"><state state="{port_state}"/>'
        f'<service name="ssh"/></port></ports></host>'
    )


def _targets(ips):
    assets = [
        {"asset_id": f"a{i}", "asset_name": f"web-0{i}", "asset_seen_ip": ip}
        for i, ip in enumerate(ips, start=1)
    ]
    data = {"injection": {"inject_content": {}}, "assets": assets}
    return Targets.extract_targets("asset-groups", "seen_ip", data, MagicMock())


def _fake_nmap(script):
    """A python process standing for nmap: writes the given chunks to stdout with
    a flush after each, then sleeps (seconds) or exits."""
    return [sys.executable, "-c", script]


_THREE_THEN_HANG = (
    "import sys, time\n"
    f"sys.stdout.write({_HEADER!r}); sys.stdout.flush()\n"
    f"for h in {[_host(ip) for ip in ('10.0.0.1', '10.0.0.2', '10.0.0.3')]!r}:\n"
    "    sys.stdout.write(h); sys.stdout.flush()\n"
    "time.sleep(60)\n"
)


class TestSplitHosts(unittest.TestCase):
    def test_complete_hosts_only(self):
        data = (_HEADER + _host("10.0.0.1") + "<host><status").encode()
        hosts, cursor = split_hosts(data, 0)
        self.assertEqual(hosts, [_host("10.0.0.1").encode()])
        data += b' state="up"/></host>'
        more, _ = split_hosts(data, cursor)
        self.assertEqual(more, [b'<host><status state="up"/></host>'])

    def test_hosthint_is_not_a_host(self):
        data = (_HEADER + "<hosthint><status/></hosthint>" + _host("10.0.0.1")).encode()
        hosts, _ = split_hosts(data, 0)
        self.assertEqual(hosts, [_host("10.0.0.1").encode()])


class TestRunNmap(unittest.TestCase):
    def test_hosts_reported_before_the_time_limit(self):
        seen = []
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as ctx:
            run_nmap(
                _fake_nmap(_THREE_THEN_HANG),
                timeout=3,
                on_host=lambda h: seen.append((time.monotonic() - started, h)),
            )
        self.assertEqual(len(seen), 3)
        # Reported as written, long before the run ended.
        self.assertTrue(all(at < 2.5 for at, _ in seen))
        self.assertIn(b"10.0.0.3", ctx.exception.output)

    def test_completed_run_returns_the_whole_output(self):
        script = (
            "import sys\n"
            f"sys.stdout.write({(_HEADER + _host('10.0.0.1') + '</nmaprun>')!r})\n"
            "sys.stderr.write('warn')\n"
            "sys.exit(0)\n"
        )
        seen = []
        result = run_nmap(_fake_nmap(script), timeout=30, on_host=seen.append)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.endswith(b"</nmaprun>"))
        self.assertEqual(result.stderr, b"warn")
        self.assertEqual(len(seen), 1)

    def test_callback_error_kills_nmap_and_propagates(self):
        def boom(_):
            raise RuntimeError("stop")

        started = time.monotonic()
        with self.assertRaises(RuntimeError):
            run_nmap(_fake_nmap(_THREE_THEN_HANG), timeout=30, on_host=boom)
        self.assertLess(time.monotonic() - started, 10)


class TestHostOutcomes(unittest.TestCase):
    def test_up_down_and_unknown_hosts(self):
        targets = _targets(["10.0.0.1", "10.0.0.2"])
        up = NmapOutputParser.host_outcomes(_host("10.0.0.1").encode(), targets)
        self.assertEqual([(o.state, o.open_ports) for o in up], [(HOST_UP, 1)])
        down = NmapOutputParser.host_outcomes(
            b'<host><status state="down"/><address addr="10.0.0.2"/></host>', targets
        )
        self.assertEqual([o.state for o in down], [HOST_DOWN])
        self.assertEqual(
            NmapOutputParser.host_outcomes(_host("10.9.9.9").encode(), targets), []
        )
        self.assertEqual(NmapOutputParser.host_outcomes(b"<host><bad", targets), [])


@patch.object(module, "intercept_dump_argument")
@patch.object(module, "OpenAEVInjectorHelper", autospec=True)
@patch.object(module, "ConfigLoader")
class TestStreamingInjector(unittest.TestCase):
    def _injector(self, m_configloader, m_helper, scan_timeout):
        m_configloader.return_value.nmap = ConfigLoaderNmap(scan_timeout=scan_timeout)
        helper = m_helper.return_value
        helper.api = MagicMock()
        helper.api.http_get.return_value = {}
        helper.injector_logger = MagicMock()
        return module.OpenAEVNmap()

    def _message(self, ips):
        target_results = _targets(ips)
        message = MagicMock()
        message.inject_id = "inject-id"
        message.contract_id = TCP_SYN_SCAN_CONTRACT
        message.selector_key = "asset-groups"
        message.target_results = target_results
        message.get_targets.return_value = target_results.targets
        message.scan_options = {}
        message.scan_timeout = None
        return message

    def test_three_hosts_then_hang_gives_three_traces_at_once(
        self, m_configloader, m_helper, _
    ):
        injector = self._injector(m_configloader, m_helper, scan_timeout=3)
        message = self._message(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        calls = injector.helper.api.inject.execution_callback
        times = []
        started = time.monotonic()
        calls.side_effect = lambda **kw: times.append(
            (time.monotonic() - started, kw["data"])
        )
        with patch.object(
            module.NmapCommandBuilder,
            "build_args",
            return_value=_fake_nmap(_THREE_THEN_HANG),
        ):
            result = injector.nmap_execution(time.time(), message)

        traces = [
            (at, d)
            for at, d in times
            if d.get("execution_context_identifiers")
            and d["execution_action"] == "command_execution"
        ]
        by_asset = {d["execution_context_identifiers"][0]: (at, d) for at, d in traces}
        self.assertEqual(len(traces), 4)
        # The three finished hosts were reported while nmap still ran.
        for asset in ("a1", "a2", "a3"):
            at, data = by_asset[asset]
            self.assertLess(at, 2.5)
            self.assertEqual(data["execution_status"], "EXECUTED")
        at, data = by_asset["a4"]
        self.assertEqual(data["execution_status"], WARNING)
        self.assertIn(TIME_LIMIT_REASON, data["execution_message"])
        # The terminal result is partial; the unfinished target is not scanned.
        self.assertEqual(result["status"], WARNING)
        states = {o.resolution.target: o.state for o in result["outcomes"]}
        self.assertEqual(states["10.0.0.4"], NOT_SCANNED)
        self.assertTrue(result["message"].startswith("nmap terminated at its 3 s"))


class TestFinalCallbackRetry(unittest.TestCase):
    @patch.object(module, "intercept_dump_argument")
    @patch.object(module.OpenAEVNmap, "nmap_execution")
    @patch.object(module, "ExecutionDetails")
    @patch.object(module, "SignatureManager")
    @patch.object(module, "build_network_configs")
    @patch.object(module, "MessageData", autospec=True)
    @patch.object(module, "OpenAEVInjectorHelper", autospec=True)
    @patch.object(module, "ConfigLoader")
    @patch("injector_common.callbacks.time.sleep")
    def test_connection_errors_are_retried_then_sent(
        self, m_sleep, m_configloader, m_helper, m_msgdata, *_mocks
    ):
        m_helper.return_value.api = MagicMock()
        m_helper.return_value.injector_logger = MagicMock()
        injector = module.OpenAEVNmap()
        message_data = MagicMock()
        message_data.inject_id = "inject-id"
        m_msgdata.return_value = message_data
        injector.nmap_execution.return_value = {"message": "done", "outputs": {}}
        callback = injector.helper.api.inject.execution_callback
        callback.side_effect = [
            requests.exceptions.ConnectionError("reset"),
            OpenAEVUpdateError("bad gateway", 502, b""),
            None,
        ]

        injector.process_message({"injection": {"inject_id": "inject-id"}})

        self.assertEqual(callback.call_count, 3)
        self.assertEqual(m_sleep.call_count, 2)
        sent = callback.call_args.kwargs["data"]
        self.assertEqual(sent["execution_action"], "complete")
        injector.signature_manager.send_signatures.assert_called_once()


if __name__ == "__main__":
    unittest.main()
