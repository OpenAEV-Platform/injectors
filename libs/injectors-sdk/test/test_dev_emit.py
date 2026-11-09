"""Tests for emitting the pending expectations of an injector run without the platform.

Feature: Emit the pending expectations of a dev run
  With --emit expectations, an injector run in dev mode also writes, on stdout, the
  pending expectations the platform would then serve to collectors: a JSON list of
  InjectExpectationOutput, the response of /api/injects/expectations/assets/{source}.
  They are built from the signatures the injector sent, the way the platform stores
  them, and from the expectations of the inject content. Piped into a collector started
  with --expectations -, they chain the injector to the collector.
"""

import io
import json
import sys
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from pydantic import TypeAdapter
from xtm_oaev_sdk import (
    Configuration,
    ExecutionDetails,
    ExecutionStatus,
    InjectExecutionActions,
    InjectExpectationOutput,
    SignatureOutputStructure,
)

CONTRACT_ID = "5c8b6c3e-0000-4000-8000-000000000001"
CONTRACT_CONTENT = {
    "contract_id": CONTRACT_ID,
    "fields": [{"key": "targets", "type": "text", "mandatory": True}],
}
CONTRACT = {
    "contract_id": CONTRACT_ID,
    "contract_labels": {"en": "TCP connect scan"},
    "contract_content": json.dumps(CONTRACT_CONTENT),
}
INJECT_ID = "8a4f1f0e-2c4b-4f43-9d5e-0b6f5b6f1a01"
DETECTION = {
    "expectation_type": "DETECTION",
    "expectation_name": "Scan detected",
    "expectation_description": "The SIEM raises the scan",
    "expectation_score": 100.0,
    "expectation_expectation_group": False,
    "expectation_expiration_time": 3600,
}
PREVENTION = {
    "expectation_type": "PREVENTION",
    "expectation_name": "Scan blocked",
    "expectation_score": 50.0,
    "expectation_expectation_group": True,
}


class Run(NamedTuple):
    exit_code: Any
    stdout: str
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


def _given_inject_message_file(tmp_path: Path, *expectations: dict) -> str:
    """Given an inject message as the platform publishes it, expecting <expectations>,
    saved to a file"""
    message = {
        "injection": {
            "inject_id": INJECT_ID,
            "inject_content": {
                "targets": "127.0.0.1",
                "expectations": list(expectations),
            },
            "inject_injector_contract": {"injector_contract_id": CONTRACT_ID},
        },
        "assets": [{"asset_id": "asset-1"}, {"asset_id": "asset-2"}],
        "assetGroups": [],
    }
    path = tmp_path / "inject.json"
    path.write_text(json.dumps(message))
    return str(path)


def _signature_target(target: dict, values: dict[str, list]) -> dict:
    return {
        "signature_target": target,
        "signature_values": [
            {
                "expectation_type": kind,
                "values": [
                    {"signature_type": name, "signature_value": value}
                    for name, value in pairs
                ],
            }
            for kind, pairs in values.items()
        ],
    }


def _given_injector_signing(*targets: dict) -> Callable[..., None]:
    """Given an injector that sends the signatures of <targets>, then completes"""

    def run(helper: Any, data: dict[str, Any]) -> None:
        inject_id = data["injection"]["inject_id"]
        helper.api.inject.execution_reception(
            inject_id=inject_id, data={"tracking_total_count": 1}
        )
        signatures = SignatureOutputStructure.model_validate(
            {"expectation_signatures": {"targets": list(targets)}}
        )
        helper.api.signature.send_signatures(
            inject_id,
            signatures,
            ExecutionDetails(
                execution_status=ExecutionStatus.EXECUTED,
                execution_action=InjectExecutionActions.DATA,
            ),
            max_payload_size=5 * 1024 * 1024,
            logger=MagicMock(),
        )
        helper.api.inject.execution_callback(
            inject_id=inject_id,
            data={
                "execution_message": "Scan done",
                "execution_status": "SUCCESS",
                "execution_action": "complete",
            },
        )

    return run


def _given_two_signed_assets() -> tuple[dict, dict]:
    """Given signatures for "asset-1" and "asset-2", for detection and prevention"""
    values = {
        "DETECTION": [("target_ipv4_address", "127.0.0.1")],
        "PREVENTION": [("target_ipv4_address", "127.0.0.1")],
    }
    return (
        _signature_target({"asset": "asset-1"}, values),
        _signature_target({"asset": "asset-2"}, values),
    )


def _when_running_and_emitting(
    tmp_path: Path, injector: Callable[..., None], message_path: str
) -> Run:
    """When the injector starts with "--dev --inject inject.json --emit expectations" """
    argv = [
        "openaev-port-scanner",
        "--dev",
        "--inject",
        message_path,
        "--emit",
        "expectations",
    ]
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        patch.object(sys, "argv", argv),
        patch.object(sys, "stdout", stdout),
        patch.object(sys, "stderr", stderr),
        patch("xtm_oaev_sdk.PingAlive.start"),
        patch.object(
            ListenQueue,
            "start",
            side_effect=AssertionError("dev mode consumed the platform queue"),
        ),
    ):
        helper = OpenAEVInjectorHelper(_given_injector_configuration(), MagicMock())
        try:
            helper.listen(lambda data: injector(helper, data))
            exit_code: Any = "listen returned without exiting"
        except SystemExit as exit_:
            exit_code = exit_.code
    return Run(exit_code, stdout.getvalue(), stderr.getvalue())


def _feed(run: Run) -> list[dict[str, Any]]:
    try:
        feed = json.loads(run.stdout)
    except ValueError:
        feed = None
    assert isinstance(
        feed, list
    ), f"Expected a JSON list of pending expectations on stdout, got {run.stdout!r}"
    return feed


def _then_feed_is_the_collector_input(run: Run) -> None:
    """Then stdout is a list of pending expectations, as the platform serves them"""
    TypeAdapter(list[InjectExpectationOutput]).validate_python(_feed(run))


def _then_feed_has(run: Run, *expected: tuple[str, str]) -> None:
    """Then the feed has exactly one pending expectation per "<target> <type>" """
    found = sorted((e["target_id"], e["inject_expectation_type"]) for e in _feed(run))
    assert found == sorted(expected)


def _then_every_expectation_is_pending_for_the_inject(run: Run) -> None:
    """Then every expectation is pending, for the inject run"""
    for expectation in _feed(run):
        assert expectation["inject_expectation_status"] == "PENDING"
        assert expectation["inject_expectation_inject"] == INJECT_ID
        assert expectation["inject_expectation_results"] == []


def _then_expectation_reads(run: Run, kind: str, **fields: Any) -> None:
    """Then the <kind> expectation has <fields>"""
    expectation = next(e for e in _feed(run) if e["inject_expectation_type"] == kind)
    for key, value in fields.items():
        assert expectation[key] == value, f"{key}: {expectation[key]!r} != {value!r}"


def _then_signatures_are(run: Run, *expected: tuple[str, str]) -> None:
    """Then every expectation carries exactly the signatures "<type> <value>" """
    for expectation in _feed(run):
        found = sorted(
            (s["type"], s["value"])
            for s in expectation["inject_expectation_signatures"]
        )
        assert found == sorted(expected)


def _then_feed_is_empty(run: Run) -> None:
    """Then the feed is an empty list"""
    assert _feed(run) == []


def _then_stderr_says(run: Run, note: str) -> None:
    """Then stderr says "<note>" """
    assert note in run.stderr, f"Expected {note!r} in {run.stderr!r}"


def _then_calls_are_on_stderr(run: Run) -> None:
    """Then the calls the injector made are written on stderr"""
    assert '"path": "/api/injects/execution/reception/' in run.stderr


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def test_one_pending_expectation_per_signed_target_and_type(tmp_path: Path) -> None:
    """It emits one pending expectation per signed target and expected type.

    Scenario: One pending expectation per signed target and type
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection and prevention, saved to a file
      And signatures for "asset-1" and "asset-2", for detection and prevention
      And an injector that sends those signatures, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the feed has exactly one pending expectation per "<target> <type>":
        | asset-1 DETECTION | asset-1 PREVENTION | asset-2 DETECTION | asset-2 PREVENTION |
      And every expectation is pending, for the inject run
      And the injector exits with code 0
    """
    path = _given_inject_message_file(tmp_path, DETECTION, PREVENTION)
    injector = _given_injector_signing(*_given_two_signed_assets())
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_feed_has(
        run,
        ("asset-1", "DETECTION"),
        ("asset-1", "PREVENTION"),
        ("asset-2", "DETECTION"),
        ("asset-2", "PREVENTION"),
    )
    _then_every_expectation_is_pending_for_the_inject(run)
    _then_exits_with(run, 0)


def test_expectations_take_their_settings_from_the_inject_content(
    tmp_path: Path,
) -> None:
    """It names, scores and expires each expectation from the inject content.

    Scenario: Expectations take their settings from the inject content
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection and prevention, saved to a file
      And an injector that sends the signatures of "asset-1" for detection and prevention, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the DETECTION expectation has name "Scan detected", expected score 100, expiration 3600, no group
      And the PREVENTION expectation has name "Scan blocked", expected score 50, the default expiration 21600, a group
    """
    path = _given_inject_message_file(tmp_path, DETECTION, PREVENTION)
    injector = _given_injector_signing(_given_two_signed_assets()[0])
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_expectation_reads(
        run,
        "DETECTION",
        inject_expectation_name="Scan detected",
        inject_expectation_description="The SIEM raises the scan",
        inject_expectation_expected_score=100.0,
        inject_expiration_time=3600,
        inject_expectation_group=False,
    )
    _then_expectation_reads(
        run,
        "PREVENTION",
        inject_expectation_name="Scan blocked",
        inject_expectation_expected_score=50.0,
        inject_expiration_time=21600,
        inject_expectation_group=True,
    )


def test_signatures_are_kept_as_the_platform_stores_them(tmp_path: Path) -> None:
    """It keeps scalars as text and drops the list and blank values the platform drops.

    Scenario: Signatures are kept as the platform stores them
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection, saved to a file
      And an injector that sends, for "asset-1" in detection, the signatures:
        | type                | value         |
        | target_ipv4_address | 127.0.0.1     |
        | port                | 22            |
        | ports_discovered    | [22, 443]     |
        | target_hostname     | "  "          |
        | target_ipv4_address | 127.0.0.1     |
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then every expectation carries exactly the signatures "target_ipv4_address 127.0.0.1" and "port 22"
      And stderr says "ports_discovered"
    """
    path = _given_inject_message_file(tmp_path, DETECTION)
    target = _signature_target(
        {"asset": "asset-1"},
        {
            "DETECTION": [
                ("target_ipv4_address", "127.0.0.1"),
                ("port", 22),
                ("ports_discovered", [22, 443]),
                ("target_hostname", "  "),
                ("target_ipv4_address", "127.0.0.1"),
            ]
        },
    )
    injector = _given_injector_signing(target)
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_signatures_are(run, ("target_ipv4_address", "127.0.0.1"), ("port", "22"))
    _then_stderr_says(run, "ports_discovered")


def test_the_agent_is_the_target_before_the_asset(tmp_path: Path) -> None:
    """It targets the agent first, then the asset, then the asset group, as the platform.

    Scenario: The agent is the target before the asset
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection, saved to a file
      And an injector that sends signatures for agent "agent-9" of "asset-1", in "group-3", then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the DETECTION expectation has target "agent-9", agent "agent-9", asset "asset-1", asset group "group-3"
    """
    path = _given_inject_message_file(tmp_path, DETECTION)
    target = _signature_target(
        {"agent": "agent-9", "asset": "asset-1", "asset_group": "group-3"},
        {"DETECTION": [("target_ipv4_address", "127.0.0.1")]},
    )
    injector = _given_injector_signing(target)
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_expectation_reads(
        run,
        "DETECTION",
        target_id="agent-9",
        inject_expectation_agent="agent-9",
        inject_expectation_asset="asset-1",
        inject_expectation_asset_group="group-3",
    )


def test_calls_leave_stdout_to_the_pending_expectations(tmp_path: Path) -> None:
    """It writes the calls on stderr when no --out is given, so stdout can be piped.

    Scenario: Calls leave stdout to the pending expectations
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection, saved to a file
      And an injector that sends the signatures of "asset-1" for detection, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the calls the injector made are written on stderr
      And stdout is a list of pending expectations, as the platform serves them
    """
    path = _given_inject_message_file(tmp_path, DETECTION)
    injector = _given_injector_signing(_given_two_signed_assets()[0])
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_calls_are_on_stderr(run)
    _then_feed_is_the_collector_input(run)


def test_pending_expectations_are_what_a_collector_reads(tmp_path: Path) -> None:
    """It emits exactly the pending-expectation shape collectors read (chain to a collector).

    Scenario: Pending expectations are what a collector reads
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection and prevention, saved to a file
      And signatures for "asset-1" and "asset-2", for detection and prevention
      And an injector that sends those signatures, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then stdout is a list of pending expectations, as the platform serves them
    """
    path = _given_inject_message_file(tmp_path, DETECTION, PREVENTION)
    injector = _given_injector_signing(*_given_two_signed_assets())
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_feed_is_the_collector_input(run)


# ---- Constraints identified ----


def test_signed_types_the_inject_does_not_expect_are_dropped(tmp_path: Path) -> None:
    """It drops signatures of a type the inject has no expectation for, saying so.

    Scenario: Signed types the inject does not expect are dropped
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection, saved to a file
      And signatures for "asset-1" and "asset-2", for detection and prevention
      And an injector that sends those signatures, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the feed has exactly one pending expectation per "asset-1 DETECTION" and "asset-2 DETECTION"
      And stderr says "PREVENTION"
    """
    path = _given_inject_message_file(tmp_path, DETECTION)
    injector = _given_injector_signing(*_given_two_signed_assets())
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_feed_has(run, ("asset-1", "DETECTION"), ("asset-2", "DETECTION"))
    _then_stderr_says(run, "PREVENTION")


def test_signatures_naming_no_target_emit_nothing(tmp_path: Path) -> None:
    """It emits an empty list, and says why, when no signature names a target.

    Scenario: Signatures naming no target emit nothing
      Given an injector configured with one TCP connect scan contract
      And an inject message as the platform publishes it, expecting detection, saved to a file
      And an injector that sends detection signatures for a target with no agent, asset or group, then completes
      When the injector starts with "--dev --inject inject.json --emit expectations"
      Then the feed is an empty list
      And stderr says "no target"
    """
    path = _given_inject_message_file(tmp_path, DETECTION)
    target = _signature_target({}, {"DETECTION": [("target_ipv4_address", "1.2.3.4")]})
    injector = _given_injector_signing(target)
    run = _when_running_and_emitting(tmp_path, injector, path)
    _then_feed_is_empty(run)
    _then_stderr_says(run, "no target")
