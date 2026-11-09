"""Tests for running a lean inject message without the platform.

Feature: Run a lean inject message
  An inject message given to --inject only needs the keys someone would edit: the
  contract id, the content, the targets. Dev mode completes the rest the way the
  platform fills it, from what it already holds: the contract from the injector's own,
  an inject id, and the contract defaults of the content. The injector then receives a
  whole platform inject message.
"""

import io
import json
import sys
from pathlib import Path
from typing import Any, NamedTuple
from unittest.mock import MagicMock, patch

from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import Configuration

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-000000000001"
CONTRACT_CONTENT = {
    "contract_id": CONTRACT_ID,
    "label": {"en": "TCP connect scan"},
    "fields": [
        {"key": "targets", "type": "text", "mandatory": True},
        {
            "key": "mode",
            "type": "select",
            "cardinality": "1",
            "defaultValue": ["fast"],
            "choices": {"fast": "Fast", "full": "Full"},
        },
    ],
}
CONTRACT = {
    "contract_id": CONTRACT_ID,
    "contract_labels": {"en": "TCP connect scan"},
    "contract_content": json.dumps(CONTRACT_CONTENT),
}


class Run(NamedTuple):
    exit_code: Any
    received: list[dict[str, Any]]
    requests: list[dict[str, Any]]
    stderr: str


def _given_injector_configuration() -> OpenAEVConfigHelper:
    """Given an injector configured with one TCP connect scan contract"""
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(
            config_hints={
                "injector_id": {"data": "4f1d-injector"},
                "injector_name": {"data": "Port scanner"},
                "injector_type": {"data": "openaev_port_scanner"},
                "injector_contracts": {"data": [CONTRACT]},
                "injector_log_level": {"data": "info"},
                "injector_json_logging": {"data": False},
            }
        )
    )


def _given_lean_message(tmp_path: Path, **content: Any) -> str:
    """Given a lean inject message naming the scan contract by id, with <content>, saved
    to a file"""
    message = {
        "injection": {
            "inject_injector_contract": {"injector_contract_id": CONTRACT_ID},
            "inject_content": {"targets": "127.0.0.1", **content},
        },
        "assets": [{"asset_id": "0d3f7d1a-lab-1"}],
    }
    path = tmp_path / "inject.json"
    path.write_text(json.dumps(message))
    return str(path)


def _given_message_naming_no_contract(tmp_path: Path) -> str:
    """Given an inject message naming no contract, saved to a file"""
    path = tmp_path / "inject.json"
    path.write_text(json.dumps({"injection": {"inject_content": {"targets": "x"}}}))
    return str(path)


def _when_running(tmp_path: Path, path: str) -> Run:
    """When the injector starts with "--dev --inject inject.json --out run.json",
    acknowledging and completing the inject"""
    out = tmp_path / "run.json"
    argv = ["openaev-port-scanner", "--dev", "--inject", path, "--out", str(out)]
    received: list[dict[str, Any]] = []
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
        helper = OpenAEVInjectorHelper(_given_injector_configuration(), MagicMock())

        def callback(data: dict[str, Any]) -> None:
            received.append(data)
            inject_id = data["injection"]["inject_id"]
            helper.api.inject.execution_reception(
                inject_id=inject_id, data={"tracking_total_count": 1}
            )
            helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": "Scan done",
                    "execution_status": "SUCCESS",
                    "execution_action": "complete",
                },
            )

        try:
            helper.listen(callback)
            exit_code: Any = "listen returned without exiting"
        except SystemExit as exit_:
            exit_code = exit_.code
    written = out.read_text() if out.exists() else ""
    requests = json.loads(written) if written else []
    return Run(exit_code, received, requests, stderr.getvalue())


def _injection(run: Run) -> dict[str, Any]:
    assert run.received, f"Expected the injector to run: {run.stderr!r}"
    return run.received[0]["injection"]


def _then_contract_is_the_injector_s_own(run: Run) -> None:
    """Then the injector receives the contract it registered, under both id paths"""
    contract = _injection(run)["inject_injector_contract"]
    assert contract["injector_contract_id"] == CONTRACT_ID
    assert contract["injector_contract_content"] == CONTRACT["contract_content"]
    assert contract["convertedContent"] == CONTRACT_CONTENT


def _then_inject_has_an_id_used_by_its_calls(run: Run) -> None:
    """Then the inject gets an id, and the calls written use it"""
    inject_id = _injection(run).get("inject_id")
    assert inject_id, "Expected the inject to get an id"
    assert [r["path"] for r in run.requests] == [
        f"/api/injects/execution/reception/{inject_id}",
        f"/api/injects/execution/callback/{inject_id}",
    ]


def _then_content_is(run: Run, content: dict[str, Any]) -> None:
    """Then the injector receives the content <content>"""
    assert _injection(run)["inject_content"] == content


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_refusal_says(run: Run, reason: str) -> None:
    """Then the refusal on stderr says "<reason>" """
    assert reason in run.stderr, f"Expected {reason!r} in {run.stderr!r}"


def test_a_lean_message_gets_the_injector_s_own_contract(tmp_path: Path) -> None:
    """It completes the contract from the injector's own, as the platform holds it.

    Scenario: A lean message gets the injector's own contract
      Given an injector configured with one TCP connect scan contract
      And a lean inject message naming the scan contract by id, saved to a file
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector receives the contract it registered, under both id paths
      And the injector exits with code 0
    """
    path = _given_lean_message(tmp_path)
    run = _when_running(tmp_path, path)
    _then_contract_is_the_injector_s_own(run)
    _then_exits_with(run, 0)


def test_a_lean_message_gets_an_inject_id(tmp_path: Path) -> None:
    """It gives a lean message without inject id one, used by every call.

    Scenario: A lean message gets an inject id
      Given an injector configured with one TCP connect scan contract
      And a lean inject message naming the scan contract by id, saved to a file
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the inject gets an id, and the calls written use it
    """
    path = _given_lean_message(tmp_path)
    run = _when_running(tmp_path, path)
    _then_inject_has_an_id_used_by_its_calls(run)


def test_a_lean_message_gets_the_contract_defaults(tmp_path: Path) -> None:
    """It completes the content with the contract defaults it leaves out.

    Scenario: A lean message gets the contract defaults
      Given an injector configured with one TCP connect scan contract
      And a lean inject message naming the scan contract by id, saved to a file
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector receives the content {"targets": "127.0.0.1", "mode": "fast"}
    """
    path = _given_lean_message(tmp_path)
    run = _when_running(tmp_path, path)
    _then_content_is(run, {"targets": "127.0.0.1", "mode": "fast"})


def test_the_content_given_wins_over_the_defaults(tmp_path: Path) -> None:
    """It keeps every content value the message gives over the contract default.

    Scenario: The content given wins over the defaults
      Given an injector configured with one TCP connect scan contract
      And a lean inject message naming the scan contract by id, with mode "full", saved to a file
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the injector receives the content {"targets": "127.0.0.1", "mode": "full"}
    """
    path = _given_lean_message(tmp_path, mode="full")
    run = _when_running(tmp_path, path)
    _then_content_is(run, {"targets": "127.0.0.1", "mode": "full"})


# ---- Constraints identified ----


def test_a_message_naming_no_contract_is_refused(tmp_path: Path) -> None:
    """It exits with code 2 when the message names no contract to complete it from.

    Scenario: A message naming no contract is refused
      Given an injector configured with one TCP connect scan contract
      And an inject message naming no contract, saved to a file
      When the injector starts with "--dev --inject inject.json --out run.json"
      Then the refusal on stderr says "names no injector contract"
      And the injector exits with code 2
    """
    path = _given_message_naming_no_contract(tmp_path)
    run = _when_running(tmp_path, path)
    _then_refusal_says(run, "names no injector contract")
    _then_exits_with(run, 2)
