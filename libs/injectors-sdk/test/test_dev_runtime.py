"""Tests for running an injector without the platform (dev mode).

Feature: Run an injector without the platform
  Started with --dev, an injector reads one inject message, exactly as the platform
  publishes it to its queue, from --inject (a file, or - for stdin). It never builds
  the platform client, never starts its heartbeat, and writes every call it would have
  made to the platform, as one JSON list of {"method", "path", "body"}, to --out. Its
  exit code says how the inject went: 0 completed, 1 failed or never completed within
  --timeout, 2 refused before running.
"""

import io
import json
import sys
import threading
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import (
    Configuration,
    ExecutionDetails,
    ExecutionStatus,
    InjectExecutionActions,
    NeedsPlatformError,
    SignatureOutputStructure,
)

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-000000000001"
CONTRACT_CONTENT = {
    "contract_id": CONTRACT_ID,
    "fields": [
        {"key": "targets", "type": "text", "mandatory": True},
        {"key": "mode", "type": "select", "choices": {"fast": "Fast", "full": "Full"}},
        {"key": "assets", "type": "asset", "mandatory": True, "cardinality": "n"},
    ],
}
CONTRACT = {
    "contract_id": CONTRACT_ID,
    "contract_labels": {"en": "TCP connect scan"},
    "contract_content": json.dumps(CONTRACT_CONTENT),
}
INJECT_ID = "8a4f1f0e-2c4b-4f43-9d5e-0b6f5b6f1a01"
RECEPTION = f"/api/injects/execution/reception/{INJECT_ID}"
CALLBACK = f"/api/injects/execution/callback/{INJECT_ID}"


class Run(NamedTuple):
    exit_code: Any
    requests: list[dict[str, Any]]
    written: str
    stderr: str
    received: list[dict[str, Any]]
    client_built: bool
    heartbeat: MagicMock
    outcome: dict[str, Any]


class _RecordingHelper(OpenAEVInjectorHelper):
    client_built = False

    def _create_default_api_client(self, config):
        _RecordingHelper.client_built = True
        return MagicMock()


def _given_injector_configuration(**hints: Any) -> OpenAEVConfigHelper:
    """Given an injector configured with one TCP connect scan contract"""
    config_hints = {
        "injector_id": {"data": "4f1d-injector"},
        "injector_name": {"data": "Port scanner"},
        "injector_type": {"data": "openaev_port_scanner"},
        "injector_contracts": {"data": [CONTRACT]},
        "injector_log_level": {"data": "info"},
        "injector_json_logging": {"data": False},
    }
    config_hints.update({key: {"data": value} for key, value in hints.items()})
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(config_hints=config_hints)
    )


def _given_inject_message(**injection: Any) -> dict[str, Any]:
    """Given an inject message as the platform publishes it, for the scan contract"""
    message = {
        "injection": {
            "inject_id": INJECT_ID,
            "inject_title": "Scan the lab",
            "inject_content": {"targets": "127.0.0.1", "mode": "fast"},
            "inject_injector_contract": {
                "injector_contract_id": CONTRACT_ID,
                "injector_contract_content": json.dumps(CONTRACT_CONTENT),
                "convertedContent": CONTRACT_CONTENT,
            },
            "inject_documents": [],
        },
        "assets": [
            {
                "asset_id": "0d3f7d1a-lab-1",
                "asset_hostname": "lab-1",
                "asset_ips": ["127.0.0.1"],
                "asset_agents": [],
            }
        ],
        "assetGroups": [],
        "attachments": None,
    }
    message["injection"].update(injection)
    return message


def _given_message_file(tmp_path: Path, message: Any) -> str:
    """Given that message saved to a file"""
    path = tmp_path / "inject.json"
    path.write_text(message if isinstance(message, str) else json.dumps(message))
    return str(path)


def _given_completing_injector(status: str = "SUCCESS") -> Callable[..., None]:
    """Given an injector that acknowledges the inject, then completes it with status
    "<status>" """

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        inject_id = data["injection"]["inject_id"]
        helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": "Scan of 127.0.0.1 done",
                "execution_output_structured": json.dumps({"ports": [22]}),
                "execution_status": status,
                "execution_duration": 2,
                "execution_action": "complete",
            },
        )

    return run


def _given_injector_that_never_completes() -> Callable[..., None]:
    """Given an injector that acknowledges the inject and never completes it"""

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        helper.api.inject.execution_reception(
            inject_id=data["injection"]["inject_id"], data={"tracking_total_count": 1}
        )

    return run


def _given_background_injector() -> Callable[..., None]:
    """Given an injector that completes the inject from a thread of its own"""
    completing = _given_completing_injector()

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        worker = threading.Thread(target=completing, args=(helper, data, outcome))
        worker.start()

    return run


def _given_signing_injector() -> Callable[..., None]:
    """Given an injector that sends the signatures of its scan, then completes"""
    completing = _given_completing_injector()

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        signatures = SignatureOutputStructure.model_validate(
            {
                "expectation_signatures": {
                    "targets": [
                        {
                            "signature_target": {"asset": "0d3f7d1a-lab-1"},
                            "signature_values": [
                                {
                                    "expectation_type": "DETECTION",
                                    "values": [
                                        {
                                            "signature_type": "target_ipv4_address",
                                            "signature_value": "127.0.0.1",
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }
            }
        )
        details = ExecutionDetails(
            execution_status=ExecutionStatus.EXECUTED,
            execution_action=InjectExecutionActions.DATA,
        )
        helper.api.signature.send_signatures(
            data["injection"]["inject_id"],
            signatures,
            details,
            max_payload_size=5 * 1024 * 1024,
            logger=MagicMock(),
        )
        completing(helper, data, outcome)

    return run


def _given_injector_calling(call: str) -> Callable[..., None]:
    """Given an injector that calls "<call>" on the platform client, then completes"""
    completing = _given_completing_injector()

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        manager, method, argument = {
            "document download": ("document", "download", "4d0c-document"),
            "target search": ("endpoint", "searchTargets", MagicMock()),
            "payload upsert": ("payload", "upsert", {"payload_name": "scan"}),
            "invalid callback": ("inject", "execution_callback", None),
        }[call]
        try:
            if call == "invalid callback":
                helper.api.inject.execution_callback(
                    inject_id=INJECT_ID,
                    data={"execution_message": "done", "execution_status": "DONE"},
                )
            else:
                getattr(getattr(helper.api, manager), method)(argument)
        except Exception as error:  # noqa: BLE001
            outcome["error"] = error
        completing(helper, data, outcome)

    return run


def _given_secret_in_environment(monkeypatch: pytest.MonkeyPatch) -> str:
    """Given the environment holds the secret SHODAN_API_KEY "env-secret-42" """
    monkeypatch.setenv("SHODAN_API_KEY", "env-secret-42")
    return "env-secret-42"


def _given_injector_leaking(secret: str) -> Callable[..., None]:
    """Given an injector whose tool output contains that secret"""

    def run(helper: Any, data: dict[str, Any], outcome: dict[str, Any]) -> None:
        inject_id = data["injection"]["inject_id"]
        helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": f"called https://api.example/?key={secret}",
                "execution_output_structured": json.dumps({"url": f"?key={secret}"}),
                "execution_status": "SUCCESS",
                "execution_action": "complete",
            },
        )

    return run


def _when_running_in_dev_mode(
    tmp_path: Path,
    injector: Callable[..., None],
    *args: str,
    configuration: OpenAEVConfigHelper | None = None,
    stdin: str | None = None,
) -> Run:
    """When the injector starts with "--dev <args> --out run.json" """
    out = tmp_path / "run.json"
    argv = ["openaev-port-scanner", "--dev", *args, "--out", str(out)]
    received: list[dict[str, Any]] = []
    outcome: dict[str, Any] = {}
    stderr = io.StringIO()
    _RecordingHelper.client_built = False
    config = configuration or _given_injector_configuration()
    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stdin", io.StringIO(stdin or "")),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start") as heartbeat,
        patch.object(
            ListenQueue,
            "start",
            side_effect=AssertionError("dev mode consumed the platform queue"),
        ),
    ):
        helper = _RecordingHelper(config, MagicMock())

        def callback(data: dict[str, Any]) -> None:
            received.append(data)
            injector(helper, data, outcome)

        try:
            helper.listen(callback)
            exit_code: Any = "listen returned without exiting"
        except SystemExit as exit_:
            exit_code = exit_.code
    written = out.read_text() if out.exists() else ""
    requests = json.loads(written) if written else []
    return Run(
        exit_code,
        requests,
        written,
        stderr.getvalue(),
        received,
        _RecordingHelper.client_built,
        heartbeat,
        outcome,
    )


def _when_building_the_helper_without_dev(
    configuration: OpenAEVConfigHelper,
) -> tuple[bool, MagicMock]:
    """When the injector helper is built without "--dev" """
    _RecordingHelper.client_built = False
    with (
        patch.object(sys, "argv", ["openaev-port-scanner"]),
        patch("xtm_oaev_sdk.PingAlive.start") as heartbeat,
    ):
        _RecordingHelper(configuration, MagicMock())
    return _RecordingHelper.client_built, heartbeat


def _then_platform_mode_is_used(client_built: bool, heartbeat: MagicMock) -> None:
    """Then the platform client is built and the heartbeat starts"""
    assert client_built is True
    heartbeat.assert_called_once()


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_platform_client_is_never_built(run: Run) -> None:
    """Then the platform client is never built"""
    assert run.client_built is False


def _then_heartbeat_never_starts(run: Run) -> None:
    """Then the heartbeat never starts"""
    run.heartbeat.assert_not_called()


def _then_requests_are(run: Run, *expected: tuple[str, str]) -> None:
    """Then the calls written are exactly "<method> <path>" """
    assert [(r["method"], r["path"]) for r in run.requests] == list(expected)


def _then_request_body_is(run: Run, index: int, body: dict[str, Any]) -> None:
    """Then the body of call <index> is exactly <body>"""
    assert run.requests[index]["body"] == body


def _then_signatures_are_sent_as_a_callback(run: Run) -> None:
    """Then the signatures are written as the execution callback carrying them"""
    body = run.requests[0]["body"]
    sent = json.loads(body["execution_output_structured"])
    target = sent["expectation_signatures"]["targets"][0]
    assert target["signature_target"] == {"asset": "0d3f7d1a-lab-1"}
    assert target["signature_values"][0]["values"] == [
        {"signature_type": "target_ipv4_address", "signature_value": "127.0.0.1"}
    ]
    assert body["execution_action"] == "data"


def _then_injector_receives(run: Run, message: dict[str, Any]) -> None:
    """Then the injector receives that message, unchanged, once"""
    assert run.received == [message]


def _then_injector_never_runs(run: Run) -> None:
    """Then the injector never runs"""
    assert run.received == []


def _then_nothing_is_written(run: Run) -> None:
    """Then no call is written"""
    assert run.requests == []


def _then_refusal_says(run: Run, reason: str) -> None:
    """Then the refusal on stderr says "<reason>" """
    assert reason in run.stderr, f"Expected {reason!r} in {run.stderr!r}"


def _then_call_fails_needing_the_platform(run: Run, call: str) -> None:
    """Then the call fails with a NeedsPlatformError naming "<call>" """
    error = run.outcome.get("error")
    assert isinstance(
        error, NeedsPlatformError
    ), f"Expected NeedsPlatformError: {error!r}"
    assert error.call == call
    assert "not available in dev mode" in str(error)


def _then_call_is_refused_as_the_platform_would(run: Run) -> None:
    """Then the call is refused with the platform's 400 answer"""
    error = run.outcome.get("error")
    assert error is not None, "Expected the call to be refused"
    assert getattr(error, "response_code", None) == 400


def _then_written_text_excludes(run: Run, secret: str) -> None:
    """Then "<secret>" appears nowhere in what is written"""
    assert run.written, "Expected something to be written"
    assert secret not in run.written


def _then_registration_is_written(run: Run) -> None:
    """Then the registration is written, with the injector contracts"""
    assert [(r["method"], r["path"]) for r in run.requests] == [
        ("POST", "/api/injectors")
    ]
    body = run.requests[0]["body"]
    assert body["injector_id"] == "4f1d-injector"
    assert body["injector_contracts"] == [CONTRACT]


def test_dev_mode_never_reaches_the_platform(tmp_path: Path) -> None:
    """It runs without building the platform client or starting the heartbeat.

    Scenario: Dev mode never reaches the platform
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the platform client is never built
      And the heartbeat never starts
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_platform_client_is_never_built(run)
    _then_heartbeat_never_starts(run)


def test_dev_mode_writes_the_calls_the_platform_would_receive(tmp_path: Path) -> None:
    """It writes the reception and the callback, path and body, as the platform takes them.

    Scenario: Dev mode writes the calls the platform would receive
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the calls written are exactly "POST <reception>" and "POST <callback>"
      And the body of call 0 is exactly {"tracking_total_count": 1}
      And the body of call 1 is exactly the callback the injector sent
      And the injector exits with code 0
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_requests_are(run, ("POST", RECEPTION), ("POST", CALLBACK))
    _then_request_body_is(run, 0, {"tracking_total_count": 1})
    _then_request_body_is(
        run,
        1,
        {
            "execution_message": "Scan of 127.0.0.1 done",
            "execution_output_structured": json.dumps({"ports": [22]}),
            "execution_status": "SUCCESS",
            "execution_duration": 2,
            "execution_action": "complete",
        },
    )
    _then_exits_with(run, 0)


def test_dev_mode_hands_the_injector_the_message_as_published(tmp_path: Path) -> None:
    """It hands the injector the inject message unchanged, both contract id paths included.

    Scenario: Dev mode hands the injector the message as published
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector receives that message, unchanged, once
    """
    message = _given_inject_message()
    path = _given_message_file(tmp_path, message)
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_injector_receives(run, message)


def test_dev_mode_reads_the_message_from_stdin(tmp_path: Path) -> None:
    """It reads the inject message from stdin when --inject is -.

    Scenario: Dev mode reads the message from stdin
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject - --out run.json", the message on stdin
      Then the injector receives that message, unchanged, once
    """
    message = _given_inject_message()
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(
        tmp_path, injector, "--inject", "-", stdin=json.dumps(message)
    )
    _then_injector_receives(run, message)


@pytest.mark.parametrize("status", ["ERROR", "COMMAND_NOT_FOUND", "TIMEOUT"])
def test_dev_mode_exits_with_one_when_the_inject_fails(
    tmp_path: Path, status: str
) -> None:
    """It exits with code 1 when the injector completes the inject with a failure.

    Scenario Outline: Dev mode exits with 1 when the inject fails
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "<status>"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector exits with code 1

      Examples:
        | status            |
        | ERROR             |
        | COMMAND_NOT_FOUND |
        | TIMEOUT           |
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_completing_injector(status)
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_exits_with(run, 1)


def test_dev_mode_exits_with_one_when_the_inject_never_completes(
    tmp_path: Path,
) -> None:
    """It exits with code 1, saying so, when no complete callback comes within --timeout.

    Scenario: Dev mode exits with 1 when the inject never completes
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that acknowledges the inject and never completes it
      When the injector starts with "--dev --inject inject.json --timeout 1 --out run.json"
      Then the refusal on stderr says "no complete callback"
      And the injector exits with code 1
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_injector_that_never_completes()
    run = _when_running_in_dev_mode(
        tmp_path, injector, "--inject", path, "--timeout", "1"
    )
    _then_refusal_says(run, "no complete callback")
    _then_exits_with(run, 1)


def test_dev_mode_waits_for_an_inject_completed_in_the_background(
    tmp_path: Path,
) -> None:
    """It waits for an inject the injector completes from a thread of its own.

    Scenario: Dev mode waits for an inject completed in the background
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that completes the inject from a thread of its own
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the calls written are exactly "POST <reception>" and "POST <callback>"
      And the injector exits with code 0
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_background_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_requests_are(run, ("POST", RECEPTION), ("POST", CALLBACK))
    _then_exits_with(run, 0)


def test_dev_mode_writes_signatures_as_the_callback_carrying_them(
    tmp_path: Path,
) -> None:
    """It writes the signatures an injector sends as the callback the platform receives.

    Scenario: Dev mode writes signatures as the callback carrying them
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that sends the signatures of its scan, then completes
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the calls written are exactly "POST <callback>", "POST <reception>" and "POST <callback>"
      And the signatures are written as the execution callback carrying them
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_signing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_requests_are(run, ("POST", CALLBACK), ("POST", RECEPTION), ("POST", CALLBACK))
    _then_signatures_are_sent_as_a_callback(run)


def test_dev_mode_writes_the_registration_when_dumping_contracts(
    tmp_path: Path,
) -> None:
    """It writes the registration the platform would receive, and runs nothing.

    Scenario: Dev mode writes the registration when dumping contracts
      Given an injector configured with one TCP connect scan contract
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --dump-contracts --out run.json"
      Then the registration is written, with the injector contracts
      And the injector never runs
      And the injector exits with code 0
    """
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--dump-contracts")
    _then_registration_is_written(run)
    _then_injector_never_runs(run)
    _then_exits_with(run, 0)


# ---- Constraints identified ----


def test_dev_mode_refuses_to_run_without_an_inject(tmp_path: Path) -> None:
    """It exits with code 2 when no inject message is given.

    Scenario: Dev mode refuses to run without an inject
      Given an injector configured with one TCP connect scan contract
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --out run.json"
      Then the injector never runs
      And the refusal on stderr says "--inject"
      And the injector exits with code 2
    """
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector)
    _then_injector_never_runs(run)
    _then_refusal_says(run, "--inject")
    _then_exits_with(run, 2)


@pytest.mark.parametrize(
    "message",
    ["{not json", json.dumps({"assets": []})],
    ids=["not JSON", "no injection"],
)
def test_dev_mode_refuses_what_is_not_a_platform_inject_message(
    tmp_path: Path, message: str
) -> None:
    """It exits with code 2, before running, when the file is not an inject message.

    Scenario Outline: Dev mode refuses what is not a platform inject message
      Given an injector configured with one TCP connect scan contract
      And <message> saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector never runs
      And no call is written
      And the refusal on stderr says "not a platform inject message"
      And the injector exits with code 2

      Examples:
        | message      |
        | not JSON     |
        | no injection |
    """
    path = _given_message_file(tmp_path, message)
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_injector_never_runs(run)
    _then_nothing_is_written(run)
    _then_refusal_says(run, "not a platform inject message")
    _then_exits_with(run, 2)


def test_dev_mode_refuses_a_contract_the_injector_does_not_serve(
    tmp_path: Path,
) -> None:
    """It exits with code 2, before running, when the inject names another contract.

    Scenario: Dev mode refuses a contract the injector does not serve
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for contract "unknown-contract"
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector never runs
      And the refusal on stderr says "unknown-contract"
      And the injector exits with code 2
    """
    message = _given_inject_message(
        inject_injector_contract={"injector_contract_id": "unknown-contract"}
    )
    path = _given_message_file(tmp_path, message)
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_injector_never_runs(run)
    _then_refusal_says(run, "unknown-contract")
    _then_exits_with(run, 2)


def test_dev_mode_refuses_content_that_fails_its_contract(tmp_path: Path) -> None:
    """It exits with code 2, before running, when the content fails its contract.

    Scenario: Dev mode refuses content that fails its contract
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, with content {"mode": "slow"}
      And that message saved to a file
      And an injector that acknowledges the inject, then completes it with status "SUCCESS"
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector never runs
      And the refusal on stderr says "targets"
      And the injector exits with code 2
    """
    message = _given_inject_message(inject_content={"mode": "slow"})
    path = _given_message_file(tmp_path, message)
    injector = _given_completing_injector()
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_injector_never_runs(run)
    _then_refusal_says(run, "targets")
    _then_exits_with(run, 2)


@pytest.mark.parametrize(
    ("call", "named"),
    [
        ("document download", "document.download"),
        ("target search", "endpoint.searchTargets"),
        ("payload upsert", "payload"),
    ],
)
def test_dev_mode_fails_the_calls_that_need_the_platform(
    tmp_path: Path, call: str, named: str
) -> None:
    """It fails a call only the platform can answer with an error naming that call.

    Scenario Outline: Dev mode fails the calls that need the platform
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that calls "<call>" on the platform client, then completes
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the call fails with a NeedsPlatformError naming "<named>"

      Examples:
        | call              | named                  |
        | document download | document.download      |
        | target search     | endpoint.searchTargets |
        | payload upsert    | payload                |
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_injector_calling(call)
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_call_fails_needing_the_platform(run, named)


def test_dev_mode_refuses_a_callback_the_platform_would_reject(
    tmp_path: Path,
) -> None:
    """It refuses an execution callback the platform would reject, writing nothing for it.

    Scenario: Dev mode refuses a callback the platform would reject
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector that calls "invalid callback" on the platform client, then completes
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the call is refused with the platform's 400 answer
      And the calls written are exactly "POST <reception>" and "POST <callback>"
    """
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_injector_calling("invalid callback")
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_call_is_refused_as_the_platform_would(run)
    _then_requests_are(run, ("POST", RECEPTION), ("POST", CALLBACK))


def test_dev_mode_redacts_secrets_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It replaces secret environment values in everything it writes.

    Scenario: Dev mode redacts secrets from the environment
      Given the environment holds the secret SHODAN_API_KEY "env-secret-42"
      And an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector whose tool output contains that secret
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then "env-secret-42" appears nowhere in what is written
    """
    secret = _given_secret_in_environment(monkeypatch)
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_injector_leaking(secret)
    run = _when_running_in_dev_mode(tmp_path, injector, "--inject", path)
    _then_written_text_excludes(run, secret)


def test_dev_mode_redacts_secrets_from_the_configuration(tmp_path: Path) -> None:
    """It replaces secret configuration values in everything it writes.

    Scenario: Dev mode redacts secrets from the configuration
      Given an injector configured with one TCP connect scan contract, and shodan_api_key "cfg-secret-42"
      And an inject message as the platform publishes it, for the scan contract
      And that message saved to a file
      And an injector whose tool output contains that secret
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then "cfg-secret-42" appears nowhere in what is written
    """
    configuration = _given_injector_configuration(shodan_api_key="cfg-secret-42")
    path = _given_message_file(tmp_path, _given_inject_message())
    injector = _given_injector_leaking("cfg-secret-42")
    run = _when_running_in_dev_mode(
        tmp_path, injector, "--inject", path, configuration=configuration
    )
    _then_written_text_excludes(run, "cfg-secret-42")


def test_platform_mode_is_unchanged_without_dev(tmp_path: Path) -> None:
    """It builds the platform client and starts the heartbeat without --dev.

    Scenario: Platform mode is unchanged without --dev
      Given an injector configured with one TCP connect scan contract
      When the injector helper is built without "--dev"
      Then the platform client is built
      And the heartbeat starts
    """
    configuration = _given_injector_configuration()
    client_built, heartbeat = _when_building_the_helper_without_dev(configuration)
    _then_platform_mode_is_used(client_built, heartbeat)
