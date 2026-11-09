"""Tests for recording and replaying an injector's outside calls in dev mode.

Feature: Record an injector's outside calls, replay them offline
  With --record PATH, a dev run writes every outside call the injector makes (its
  tool's API over HTTP, its scanner commands) and the answers to a tape. With --replay
  PATH, the same run answers those calls from the tape: offline, with no API and no
  scanner, it writes the same platform calls.
"""

import http.server
import io
import json
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import Configuration

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-000000000001"
CONTRACT = {
    "contract_id": CONTRACT_ID,
    "contract_labels": {"en": "Host lookup"},
    "contract_content": json.dumps(
        {"contract_id": CONTRACT_ID, "fields": [{"key": "ip", "type": "text"}]}
    ),
}
API_KEY = "tool-key-12345"


class Run(NamedTuple):
    exit_code: Any
    requests: list[dict[str, Any]]
    stderr: str


class _ToolApi(http.server.BaseHTTPRequestHandler):
    calls = 0

    def log_message(self, *_: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        type(self).calls += 1
        body = json.dumps({"host": self.path.split("/")[-1].split("?")[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ToolApi:
    """The injector's tool API, running locally, which a test can shut down."""

    def __init__(self) -> None:
        _ToolApi.calls = 0
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ToolApi)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self.running = True

    def shut_down(self) -> None:
        if self.running:
            self._server.shutdown()
            self._server.server_close()
            self.running = False


@pytest.fixture
def tool_api() -> Any:
    api = ToolApi()
    yield api
    api.shut_down()


def _given_injector_configuration() -> OpenAEVConfigHelper:
    """Given an injector configured with one host lookup contract, and its tool key"""
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(
            config_hints={
                "injector_id": {"data": "4f1d-injector"},
                "injector_name": {"data": "Host lookup"},
                "injector_type": {"data": "openaev_host_lookup"},
                "injector_contracts": {"data": [CONTRACT]},
                "injector_log_level": {"data": "info"},
                "injector_json_logging": {"data": False},
                "tool_api_key": {"data": API_KEY},
            }
        )
    )


def _given_inject_message(tmp_path: Path) -> str:
    """Given a lean inject message looking up 10.0.0.5, saved to a file"""
    path = tmp_path / "inject.json"
    path.write_text(
        json.dumps(
            {
                "injection": {
                    "inject_id": "8a4f1f0e-2c4b-4f43-9d5e-0b6f5b6f1a01",
                    "inject_injector_contract": {"injector_contract_id": CONTRACT_ID},
                    "inject_content": {"ip": "10.0.0.5"},
                }
            }
        )
    )
    return str(path)


def _given_looking_up_injector(api_url: str) -> Callable[..., None]:
    """Given an injector that asks its tool API about the host, runs a scanner command,
    and completes with both answers"""

    def run(helper: Any, data: dict[str, Any]) -> None:
        inject_id = data["injection"]["inject_id"]
        ip = data["injection"]["inject_content"]["ip"]
        helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        with urllib.request.urlopen(f"{api_url}/hosts/{ip}?key={API_KEY}") as answer:
            host = json.loads(answer.read())["host"]
        scan = subprocess.run(
            [sys.executable, "-c", f"print('22/tcp open on {ip}')"],
            capture_output=True,
            text=True,
            check=True,
        )
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": f"{host}: {scan.stdout.strip()}",
                "execution_status": "SUCCESS",
                "execution_action": "complete",
            },
        )

    return run


def _given_the_api_shut_down(api: ToolApi) -> None:
    """Given the tool API is shut down: nothing answers on its URL any more"""
    api.shut_down()


def _when_running(tmp_path: Path, injector: Callable[..., None], *args: str) -> Run:
    """When the injector starts with "--dev --inject inject.json <args> --out run.json" """
    out = tmp_path / "run.json"
    out.unlink(missing_ok=True)
    argv = ["openaev-host-lookup", "--dev", *args, "--out", str(out)]
    stderr = io.StringIO()
    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start"),
        patch.object(
            ListenQueue,
            "start",
            side_effect=AssertionError("dev mode consumed the platform queue"),
        ),
    ):
        try:
            helper = OpenAEVInjectorHelper(_given_injector_configuration(), MagicMock())
            helper.listen(lambda data: injector(helper, data))
            exit_code: Any = "listen returned without exiting"
        except SystemExit as exit_:
            exit_code = exit_.code
    written = out.read_text() if out.exists() else ""
    requests = json.loads(written) if written else []
    return Run(exit_code, requests, stderr.getvalue())


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_completes_with(run: Run, message: str) -> None:
    """Then the injector completes the inject with "<message>" """
    completes = [r["body"] for r in run.requests if r["path"].endswith("a01")]
    assert completes and completes[-1].get("execution_message") == message, completes


def _then_tape_holds_an_http_call_and_a_command(path: Path) -> None:
    """Then the tape holds the tool API call and the scanner command"""
    assert path.exists(), f"Expected a tape at {path}"
    kinds = [call["kind"] for call in json.loads(path.read_text())["calls"]]
    assert kinds == ["http", "command"], kinds


def _then_tape_names_the_daemon(path: Path) -> None:
    """Then the tape's header names the injector "Host lookup" """
    assert json.loads(path.read_text())["daemon"] == "Host lookup"


def _then_tape_excludes(path: Path, secret: str) -> None:
    """Then "<secret>" appears nowhere on the tape"""
    assert secret not in path.read_text()


def _then_same_platform_calls(replayed: Run, recorded: Run) -> None:
    """Then the platform calls written are the same as when recording"""
    assert replayed.requests == recorded.requests


def _then_refusal_says(run: Run, reason: str) -> None:
    """Then the refusal on stderr says "<reason>" """
    assert reason in run.stderr, f"Expected {reason!r} in {run.stderr!r}"


def test_recording_writes_the_injector_s_outside_calls(
    tmp_path: Path, tool_api: ToolApi
) -> None:
    """It runs the inject for real and writes its tool API call and command to the tape.

    Scenario: Recording writes the injector's outside calls
      Given an injector configured with one host lookup contract, and its tool key
      And a lean inject message looking up 10.0.0.5, saved to a file
      And an injector that asks its tool API about the host, runs a scanner command, and completes with both answers
      When the injector starts with "--dev --inject inject.json --record tape.json --out run.json"
      Then the injector completes the inject with "10.0.0.5: 22/tcp open on 10.0.0.5"
      And the tape holds the tool API call and the scanner command
      And "tool-key-12345" appears nowhere on the tape
      And the injector exits with code 0
    """
    tape = tmp_path / "tape.json"
    message = _given_inject_message(tmp_path)
    injector = _given_looking_up_injector(tool_api.url)
    run = _when_running(tmp_path, injector, "--inject", message, "--record", str(tape))
    _then_completes_with(run, "10.0.0.5: 22/tcp open on 10.0.0.5")
    _then_tape_holds_an_http_call_and_a_command(tape)
    _then_tape_names_the_daemon(tape)
    _then_tape_excludes(tape, API_KEY)
    _then_exits_with(run, 0)


def test_replaying_runs_the_inject_offline(tmp_path: Path, tool_api: ToolApi) -> None:
    """It runs the same inject from the tape, with the tool API shut down.

    Scenario: Replaying runs the inject offline
      Given an injector configured with one host lookup contract, and its tool key
      And a lean inject message looking up 10.0.0.5, saved to a file
      And an injector that asks its tool API about the host, runs a scanner command, and completes with both answers
      And the injector ran with "--record tape.json"
      And the tool API is shut down: nothing answers on its URL any more
      When the injector starts with "--dev --inject inject.json --replay tape.json --out run.json"
      Then the platform calls written are the same as when recording
      And the injector exits with code 0
    """
    tape = tmp_path / "tape.json"
    message = _given_inject_message(tmp_path)
    injector = _given_looking_up_injector(tool_api.url)
    recorded = _when_running(
        tmp_path, injector, "--inject", message, "--record", str(tape)
    )
    _given_the_api_shut_down(tool_api)
    replayed = _when_running(
        tmp_path, injector, "--inject", message, "--replay", str(tape)
    )
    _then_same_platform_calls(replayed, recorded)
    _then_exits_with(replayed, 0)


# ---- Constraints identified ----


def test_record_and_replay_together_are_refused(
    tmp_path: Path, tool_api: ToolApi
) -> None:
    """It exits with code 2 when asked to record and replay at once.

    Scenario: Record and replay together are refused
      Given an injector configured with one host lookup contract, and its tool key
      And a lean inject message looking up 10.0.0.5, saved to a file
      When the injector starts with "--dev --inject inject.json --record a.tape.json --replay b.tape.json --out run.json"
      Then the refusal on stderr says "--record" and "--replay"
      And the injector exits with code 2
    """
    message = _given_inject_message(tmp_path)
    injector = _given_looking_up_injector(tool_api.url)
    run = _when_running(
        tmp_path,
        injector,
        "--inject",
        message,
        "--record",
        str(tmp_path / "a.tape.json"),
        "--replay",
        str(tmp_path / "b.tape.json"),
    )
    _then_refusal_says(run, "--record")
    _then_refusal_says(run, "--replay")
    _then_exits_with(run, 2)


def test_a_tape_that_cannot_be_replayed_is_refused(
    tmp_path: Path, tool_api: ToolApi
) -> None:
    """It exits with code 2, before running, when the replay tape cannot be read.

    Scenario: A tape that cannot be replayed is refused
      Given an injector configured with one host lookup contract, and its tool key
      And a lean inject message looking up 10.0.0.5, saved to a file
      And a tape file that is not JSON
      When the injector starts with "--dev --inject inject.json --replay tape.json --out run.json"
      Then the refusal on stderr says "not a JSON tape"
      And the injector exits with code 2
    """
    tape = tmp_path / "tape.json"
    tape.write_text("calls: []")
    message = _given_inject_message(tmp_path)
    injector = _given_looking_up_injector(tool_api.url)
    run = _when_running(tmp_path, injector, "--inject", message, "--replay", str(tape))
    _then_refusal_says(run, "not a JSON tape")
    _then_exits_with(run, 2)
