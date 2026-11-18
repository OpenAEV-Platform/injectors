"""Tests for the configuration schema dump shared by the injectors.

Feature: Configuration schema dump of an injector
  An injector dumps its configuration schema when started with --dump-config-schema.
  The same command line can carry dev and tool flags the dump does not own: it must
  ignore them instead of making the injector exit.
"""

import sys
from typing import Any, NamedTuple
from unittest.mock import MagicMock

import pytest

from injector_common.dump_config import intercept_dump_argument

SCHEMA = '{"title": "nmap injector configuration"}'


class Interception(NamedTuple):
    exit_code: Any
    output: str


def _given_injector_configuration() -> MagicMock:
    """Given an injector configuration with a schema"""
    configuration = MagicMock()
    configuration.schema.return_value = SCHEMA
    return configuration


def _given_process_command_line(monkeypatch: pytest.MonkeyPatch, *args: str) -> None:
    """Given the process command line contains "<args>" """
    monkeypatch.setattr(sys, "argv", ["openaev-nmap", *args])


def _when_intercepting_the_dump_argument(
    configuration: MagicMock, capsys: pytest.CaptureFixture
) -> Interception:
    """When the injector intercepts the dump argument"""
    try:
        intercept_dump_argument(configuration)
    except SystemExit as exit_:
        return Interception(exit_.code, capsys.readouterr().out)
    return Interception(None, capsys.readouterr().out)


def _then_injector_goes_on(interception: Interception) -> None:
    """Then the injector goes on without exiting"""
    assert (
        interception.exit_code is None
    ), f"Expected the injector to go on, it exited with {interception.exit_code}"


def _then_injector_exits_with(interception: Interception, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert interception.exit_code == code


def _then_schema_is_printed(interception: Interception) -> None:
    """Then the configuration schema is printed"""
    assert interception.output == f"{SCHEMA}\n"


def _then_nothing_is_printed(interception: Interception) -> None:
    """Then nothing is printed"""
    assert interception.output == ""


def test_flags_the_dump_does_not_own_are_ignored(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """It lets the injector go on when its command line carries dev and tool flags.

    Scenario: Flags the dump does not own are ignored
      Given an injector configuration with a schema
      And the process command line contains "--dev --inject inject.json --ports 22"
      When the injector intercepts the dump argument
      Then the injector goes on without exiting
      And nothing is printed
    """
    configuration = _given_injector_configuration()
    _given_process_command_line(
        monkeypatch, "--dev", "--inject", "inject.json", "--ports", "22"
    )
    interception = _when_intercepting_the_dump_argument(configuration, capsys)
    _then_injector_goes_on(interception)
    _then_nothing_is_printed(interception)


def test_schema_is_still_dumped_among_other_flags(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """It prints the schema and exits with code 0, dev flags or not.

    Scenario: The schema is still dumped among other flags
      Given an injector configuration with a schema
      And the process command line contains "--dev --dump-config-schema"
      When the injector intercepts the dump argument
      Then the configuration schema is printed
      And the injector exits with code 0
    """
    configuration = _given_injector_configuration()
    _given_process_command_line(monkeypatch, "--dev", "--dump-config-schema")
    interception = _when_intercepting_the_dump_argument(configuration, capsys)
    _then_schema_is_printed(interception)
    _then_injector_exits_with(interception, 0)


def test_nothing_happens_without_flags(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """It lets the injector go on, printing nothing, when no flag is given.

    Scenario: Nothing happens without flags
      Given an injector configuration with a schema
      And the process command line contains ""
      When the injector intercepts the dump argument
      Then the injector goes on without exiting
      And nothing is printed
    """
    configuration = _given_injector_configuration()
    _given_process_command_line(monkeypatch)
    interception = _when_intercepting_the_dump_argument(configuration, capsys)
    _then_injector_goes_on(interception)
    _then_nothing_is_printed(interception)
