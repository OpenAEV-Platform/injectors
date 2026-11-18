"""Tests for the contract helpers of an injector run without the platform.

Feature: Write an inject message from an injector's contracts
  To run an injector in dev mode you need an inject message for one of its contracts.
  --list-contracts lists the contracts the injector serves. --new-inject CONTRACT writes
  a lean inject message for one of them (the platform's own keys, only those to edit),
  its content prefilled the way the platform builds a new inject, with a target type
  dev mode can run; stderr guides through the fields and says which mandatory ones are
  still to fill. Dev mode completes the rest when the message is run.
"""

import io
import json
import sys
from pathlib import Path
from typing import Any, Callable, NamedTuple
from unittest.mock import MagicMock, patch

from injectors_sdk import ListenQueue, OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import Configuration

TCP_ID = "5c8b6c3e-0000-4000-8000-0000000000a1"
UDP_ID = "5c8b6c3e-0000-4000-8000-0000000000a2"
SWEEP_ID = "5c8b6c3e-0000-4000-8000-0000000000a3"
DETECTION = {
    "expectation_type": "DETECTION",
    "expectation_name": "Scan detected",
    "expectation_score": 100,
    "expectation_is_predefined": True,
}
PREVENTION = {
    "expectation_type": "PREVENTION",
    "expectation_name": "Scan blocked",
    "expectation_score": 100,
    "expectation_is_predefined": False,
}
TCP_FIELDS = [
    {
        "key": "target_selector",
        "type": "select",
        "mandatory": True,
        "cardinality": "1",
        "defaultValue": ["asset-groups"],
        "choices": {
            "assets": "Assets",
            "asset-groups": "Asset groups",
            "manual": "Manual",
        },
    },
    {
        "key": "asset_groups",
        "type": "asset-group",
        "cardinality": "n",
        "defaultValue": [],
        "mandatoryConditionFields": ["target_selector"],
        "mandatoryConditionValues": {"target_selector": "asset-groups"},
    },
    {
        "key": "ports",
        "type": "tuple",
        "mandatory": True,
        "cardinality": "n",
        "defaultValue": ["22", "443"],
    },
    {"key": "timeout", "type": "text", "cardinality": "1", "defaultValue": "30"},
    {"key": "verbose", "type": "checkbox", "defaultValue": False},
    {"key": "teams", "type": "team", "cardinality": "n", "defaultValue": ["t-1"]},
    {
        "key": "expectations",
        "type": "expectation",
        "cardinality": "n",
        "defaultValue": [],
        "availableExpectations": [DETECTION, PREVENTION],
    },
]


def _contract(contract_id: str, label: str, fields: list[dict]) -> dict[str, Any]:
    content = {"contract_id": contract_id, "label": {"en": label}, "fields": fields}
    return {
        "contract_id": contract_id,
        "contract_labels": {"en": label, "fr": f"{label} (fr)"},
        "contract_content": json.dumps(content),
    }


CONTRACTS = [
    _contract(TCP_ID, "Port scan - TCP connect", TCP_FIELDS),
    _contract(UDP_ID, "Port scan - UDP", TCP_FIELDS),
    _contract(
        SWEEP_ID, "Ping sweep", [{"key": "range", "type": "text", "mandatory": True}]
    ),
]


class Run(NamedTuple):
    exit_code: Any
    stdout: str
    stderr: str
    received: list[Any]


def _given_injector_with_three_contracts() -> OpenAEVConfigHelper:
    """Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and
    "Ping sweep" """
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(
            config_hints={
                "injector_id": {"data": "4f1d-injector"},
                "injector_name": {"data": "Port scanner"},
                "injector_type": {"data": "openaev_port_scanner"},
                "injector_contracts": {"data": CONTRACTS},
                "injector_log_level": {"data": "info"},
                "injector_json_logging": {"data": False},
            }
        )
    )


def _given_completing_injector() -> Callable[..., None]:
    """Given an injector that acknowledges the inject, then completes it"""

    def run(helper: Any, data: dict[str, Any]) -> None:
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

    return run


def _given_written_message_file(tmp_path: Path, run: Run) -> str:
    """Given the written message saved to a file"""
    path = tmp_path / "inject.json"
    path.write_text(run.stdout)
    return str(path)


def _when_running(*args: str, injector: Callable[..., None] | None = None) -> Run:
    """When the injector starts with "--dev <args>" """
    argv = ["openaev-port-scanner", "--dev", *args]
    stdout, stderr = io.StringIO(), io.StringIO()
    received: list[Any] = []
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
        helper = OpenAEVInjectorHelper(
            _given_injector_with_three_contracts(), MagicMock()
        )

        def callback(data: dict[str, Any]) -> None:
            received.append(data)
            if injector is not None:
                injector(helper, data)

        try:
            helper.listen(callback)
            exit_code: Any = "listen returned without exiting"
        except SystemExit as exit_:
            exit_code = exit_.code
    return Run(exit_code, stdout.getvalue(), stderr.getvalue(), received)


def _message(run: Run) -> dict[str, Any]:
    try:
        message = json.loads(run.stdout)
    except ValueError:
        message = None
    assert isinstance(
        message, dict
    ), f"Expected an inject message on stdout, got {run.stdout!r}"
    return message


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_injector_never_runs(run: Run) -> None:
    """Then the injector never runs"""
    assert run.received == []


def _then_listing_shows(run: Run, *contracts: tuple[str, str]) -> None:
    """Then stdout lists one line per contract, with its id and its label"""
    lines = [line for line in run.stdout.splitlines() if line.strip()]
    assert len(lines) == len(contracts), f"Expected {len(contracts)} lines: {lines}"
    for line, (contract_id, label) in zip(lines, contracts):
        assert contract_id in line and label in line, f"{line!r}"


def _then_listing_shows_targets(run: Run, contract_id: str, targets: str) -> None:
    """Then the line of <contract_id> shows the targets "<targets>" """
    line = next(line for line in run.stdout.splitlines() if contract_id in line)
    assert targets in line, f"Expected {targets!r} in {line!r}"


def _then_message_is_lean_for(run: Run, contract_id: str) -> None:
    """Then the message names contract <contract_id> by its id only, with no
    contract content and no inject id to copy around"""
    message = _message(run)
    assert message["injection"]["inject_injector_contract"] == {
        "injector_contract_id": contract_id
    }
    assert "inject_id" not in message["injection"]


def _then_content_is(run: Run, content: dict[str, Any]) -> None:
    """Then the inject content is exactly <content>"""
    assert _message(run)["injection"]["inject_content"] == content


def _then_stderr_says(run: Run, *notes: str) -> None:
    """Then stderr says "<notes>" """
    for note in notes:
        assert note in run.stderr, f"Expected {note!r} in {run.stderr!r}"


def _then_guide_line_reads(run: Run, key: str, *parts: str) -> None:
    """Then the field guide line of "<key>" reads "<parts>" """
    line = next(
        (line for line in run.stderr.splitlines() if line.split()[:1] == [key]), None
    )
    assert line is not None, f"Expected a guide line for {key} in {run.stderr!r}"
    for part in parts:
        assert part in line, f"Expected {part!r} in {line!r}"


def _then_nothing_is_written(run: Run) -> None:
    """Then nothing is written on stdout"""
    assert run.stdout == ""


def test_list_contracts_shows_each_contract() -> None:
    """It lists every contract the injector serves, by id and label, and exits.

    Scenario: --list-contracts shows each contract
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --list-contracts"
      Then stdout lists one line per contract, with its id and its label
      And the line of the TCP connect contract shows the targets "assets, asset-groups, manual"
      And the injector exits with code 0
      And the injector never runs
    """
    run = _when_running("--list-contracts")
    _then_listing_shows(
        run,
        (TCP_ID, "Port scan - TCP connect"),
        (UDP_ID, "Port scan - UDP"),
        (SWEEP_ID, "Ping sweep"),
    )
    _then_listing_shows_targets(run, TCP_ID, "assets, asset-groups, manual")
    _then_exits_with(run, 0)
    _then_injector_never_runs(run)


def test_new_inject_writes_a_lean_inject_message() -> None:
    """It writes only the keys to edit, naming the contract by its id.

    Scenario: --new-inject writes a lean inject message
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject <TCP connect id>"
      Then the message names the TCP connect contract by its id only, with no contract content and no inject id to copy around
      And the injector exits with code 0
      And the injector never runs
    """
    run = _when_running("--new-inject", TCP_ID)
    _then_message_is_lean_for(run, TCP_ID)
    _then_exits_with(run, 0)
    _then_injector_never_runs(run)


def test_new_inject_prefills_the_content_as_the_platform_does() -> None:
    """It prefills the content the way the platform's inject form fills a new inject.

    Scenario: --new-inject prefills the content as the platform does
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject <TCP connect id>"
      Then the inject content is exactly:
        | field           | value                      | because                                  |
        | target_selector | "manual"                   | the first target type dev mode can run   |
        | ports           | ["22", "443"]              | several values: the whole default        |
        | timeout         | "30"                       | the default, as declared                 |
        | verbose         | false                      | the default, as declared                 |
        | expectations    | [the predefined detection] | the predefined available expectations    |
      And asset_groups and teams are left out: targets and teams travel next to the content
    """
    run = _when_running("--new-inject", TCP_ID)
    _then_content_is(
        run,
        {
            "target_selector": "manual",
            "ports": ["22", "443"],
            "timeout": "30",
            "verbose": False,
            "expectations": [DETECTION],
        },
    )


def test_new_inject_picks_a_target_type_dev_mode_can_run() -> None:
    """It replaces a default target type dev mode cannot run, saying why.

    Scenario: --new-inject picks a target type dev mode can run
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject <TCP connect id>"
      Then stderr says "target_selector", "manual" and "asset groups need the platform"
    """
    run = _when_running("--new-inject", TCP_ID)
    _then_stderr_says(
        run, "target_selector", "manual", "asset groups need the platform"
    )


def test_new_inject_guides_through_the_fields() -> None:
    """It describes each field on stderr: type, when it is mandatory, choices, value.

    Scenario: --new-inject guides through the fields
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject <TCP connect id>"
      Then the field guide line of "target_selector" reads "select", "mandatory", "manual" and "asset-groups"
      And the field guide line of "asset_groups" reads "asset-group", "when target_selector" and "assetGroups"
      And the field guide line of "timeout" reads "text" and "optional"
    """
    run = _when_running("--new-inject", TCP_ID)
    _then_guide_line_reads(
        run, "target_selector", "select", "mandatory", "manual", "asset-groups"
    )
    _then_guide_line_reads(
        run, "asset_groups", "asset-group", "when target_selector", "assetGroups"
    )
    _then_guide_line_reads(run, "timeout", "text", "optional")


def test_new_inject_says_which_mandatory_fields_are_still_to_fill() -> None:
    """It says on stderr which mandatory fields the prefilled content still misses.

    Scenario: --new-inject says which mandatory fields are still to fill
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject ping"
      Then stderr says "still to fill" and "range"
    """
    run = _when_running("--new-inject", "ping")
    _then_stderr_says(run, "still to fill", "range")


def test_new_inject_names_the_contract_by_a_piece_of_its_label() -> None:
    """It finds the contract by a piece of its label, whatever the case.

    Scenario: --new-inject names the contract by a piece of its label
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject tcp CONNECT"
      Then the message names the TCP connect contract by its id only
    """
    run = _when_running("--new-inject", "tcp CONNECT")
    _then_message_is_lean_for(run, TCP_ID)


def test_the_written_message_runs_as_is_once_complete(tmp_path: Path) -> None:
    """It writes a message dev mode runs as is when nothing is left to fill.

    Scenario: The written message runs as is once complete
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      And the message written by "--dev --new-inject <TCP connect id>"
      And the written message saved to a file
      And an injector that acknowledges the inject, then completes it
      When the injector starts with "--dev --inject inject.json"
      Then the injector exits with code 0
    """
    written = _when_running("--new-inject", TCP_ID)
    path = _given_written_message_file(tmp_path, written)
    injector = _given_completing_injector()
    run = _when_running(
        "--inject", path, "--out", str(tmp_path / "run.json"), injector=injector
    )
    _then_exits_with(run, 0)


# ---- Constraints identified ----


def test_new_inject_refuses_an_unknown_contract() -> None:
    """It exits with code 2, listing the contracts, when the name matches none.

    Scenario: --new-inject refuses an unknown contract
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject traceroute"
      Then nothing is written on stdout
      And stderr says "traceroute", "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      And the injector exits with code 2
    """
    run = _when_running("--new-inject", "traceroute")
    _then_nothing_is_written(run)
    _then_stderr_says(
        run, "traceroute", "Port scan - TCP connect", "Port scan - UDP", "Ping sweep"
    )
    _then_exits_with(run, 2)


def test_new_inject_refuses_an_ambiguous_contract() -> None:
    """It exits with code 2, listing the matches, when the name matches several.

    Scenario: --new-inject refuses an ambiguous contract
      Given an injector serving "Port scan - TCP connect", "Port scan - UDP" and "Ping sweep"
      When the injector starts with "--dev --new-inject port scan"
      Then nothing is written on stdout
      And stderr says "Port scan - TCP connect" and "Port scan - UDP"
      And the injector exits with code 2
    """
    run = _when_running("--new-inject", "port scan")
    _then_nothing_is_written(run)
    _then_stderr_says(run, "Port scan - TCP connect", "Port scan - UDP")
    _then_exits_with(run, 2)
