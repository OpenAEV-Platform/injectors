"""Tests for the dev options of an injector.

Feature: Injector dev options
  An injector reads the dev options common to every daemon plus its own: the inject
  message to run, what to emit, and its contract helpers. It never reads the options of
  a collector, and like every daemon it never acts on a flag that is not its own.
"""

from typing import Any, Callable

import injectors_sdk
import pytest

INJECTOR_OPTIONS = (
    "--inject",
    "--timeout",
    "--emit",
    "--dump-contracts",
    "--list-contracts",
    "--new-inject",
)
COMMON_OPTIONS = ("--dev", "-h", "--out", "--record", "--replay")


def _given_injector_dev_options_reader() -> Callable[..., Any]:
    """Given the injectors SDK exposes the injector dev options"""
    reader = getattr(injectors_sdk, "injector_dev_options", None)
    assert reader is not None, "Expected injectors_sdk.injector_dev_options"
    return reader


def _given_injector_dev_help() -> Callable[[], str]:
    """Given the injectors SDK exposes the injector dev help"""
    helper = getattr(injectors_sdk, "injector_dev_help", None)
    assert helper is not None, "Expected injectors_sdk.injector_dev_help"
    return helper


def _given_command_line(*args: str) -> list[str]:
    """Given an injector command line with "<args>" """
    return list(args)


def _when_reading_dev_options(reader: Callable[..., Any], argv: list[str]) -> Any:
    """When the injector dev options are read"""
    return reader(argv)


def _when_reading_the_help(helper: Callable[[], str]) -> str:
    """When the injector dev help is read"""
    return helper()


def _then_options_are(options: Any, **expected: Any) -> None:
    """Then the options are <expected>"""
    actual = {name: getattr(options, name) for name in expected}
    assert actual == expected


def _then_options_have_no(options: Any, *names: str) -> None:
    """Then the options have no <names>"""
    present = [name for name in names if hasattr(options, name)]
    assert present == [], f"Expected no {present} on the injector options"


def _then_help_groups(text: str, heading: str, *options: str) -> None:
    """Then the help section "<heading>" lists exactly <options>"""
    section = text.split(f"{heading}:", 1)[1].split("\n\n", 1)[0]
    listed = tuple(
        token.rstrip(",")
        for line in section.splitlines()
        for token in line.split()
        if token.startswith("-") and line.lstrip().startswith(token)
    )
    assert listed == options, f"Expected {options} under {heading}, got {listed}"


def _then_help_has_no_section(text: str, heading: str) -> None:
    """Then the help has no "<heading>" section"""
    assert f"{heading}:" not in text


def test_injector_dev_mode_is_off_without_dev_flags() -> None:
    """It reports dev mode off, every injector option unset, without dev flags.

    Scenario: Injector dev mode is off without dev flags
      Given the injectors SDK exposes the injector dev options
      And an injector command line with ""
      When the injector dev options are read
      Then the options are disabled, with no inject, no emit and no contract helper
    """
    reader = _given_injector_dev_options_reader()
    options = _when_reading_dev_options(reader, _given_command_line())
    _then_options_are(
        options,
        enabled=False,
        inject=None,
        emit=(),
        dump_contracts=False,
        list_contracts=False,
        new_inject=None,
    )


def test_every_injector_dev_flag_is_exposed_with_the_common_ones() -> None:
    """It exposes the injector's own dev flags next to the common ones.

    Scenario: Every injector dev flag is exposed with the common ones
      Given the injectors SDK exposes the injector dev options
      And an injector command line with:
        | flag             | value            |
        | --dev            |                  |
        | --inject         | inject.json      |
        | --emit           | expectations     |
        | --out            | run.json         |
        | --replay         | shodan.tape.json |
        | --dump-contracts |                  |
        | --list-contracts |                  |
        | --new-inject     | ip enum          |
      When the injector dev options are read
      Then the options carry each value given
    """
    reader = _given_injector_dev_options_reader()
    argv = _given_command_line(
        "--dev",
        "--inject",
        "inject.json",
        "--emit",
        "expectations",
        "--out",
        "run.json",
        "--replay",
        "shodan.tape.json",
        "--dump-contracts",
        "--list-contracts",
        "--new-inject",
        "ip enum",
    )
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(
        options,
        enabled=True,
        inject="inject.json",
        emit=("expectations",),
        out="run.json",
        record=None,
        replay="shodan.tape.json",
        dump_contracts=True,
        list_contracts=True,
        new_inject="ip enum",
        help=False,
    )


def test_repeated_emit_flags_are_all_kept_in_order() -> None:
    """It keeps every emitted kind, in the order given.

    Scenario: Repeated emit flags are all kept, in order
      Given the injectors SDK exposes the injector dev options
      And an injector command line with "--dev --emit expectations --emit traces"
      When the injector dev options are read
      Then the options emit "expectations, traces"
    """
    reader = _given_injector_dev_options_reader()
    argv = _given_command_line("--dev", "--emit", "expectations", "--emit", "traces")
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(options, emit=("expectations", "traces"))


def test_injector_never_reads_the_collector_options() -> None:
    """It holds no collector option, and leaves them alone on its command line.

    Scenario: An injector never reads the collector options
      Given the injectors SDK exposes the injector dev options
      And an injector command line with "--dev --expectations - --once"
      When the injector dev options are read
      Then the options have no expectations and no once
      And the options are enabled
    """
    reader = _given_injector_dev_options_reader()
    argv = _given_command_line("--dev", "--expectations", "-", "--once")
    options = _when_reading_dev_options(reader, argv)
    _then_options_have_no(options, "expectations", "once")
    _then_options_are(options, enabled=True)


@pytest.mark.parametrize(
    ("argv", "option", "unset"),
    [
        (["--dev", "--inj", "inject.json"], "inject", None),
        (["--dev", "--em", "expectations"], "emit", ()),
        (["--dev", "--new", "ip enum"], "new_inject", None),
        (["--dev", "--list"], "list_contracts", False),
    ],
    ids=["inject", "emit", "new inject", "list contracts"],
)
def test_injector_options_are_read_only_under_their_full_name(
    argv: list[str], option: str, unset: Any
) -> None:
    """It reads an injector option only under its full name, never an abbreviation.

    Scenario Outline: Injector options are read only under their full name
      Given the injectors SDK exposes the injector dev options
      And an injector command line with "<argv>"
      When the injector dev options are read
      Then the options leave <option> unset
    """
    reader = _given_injector_dev_options_reader()
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(options, **{option: unset})


def test_injector_dev_help_lists_the_common_and_injector_options() -> None:
    """It lists the common options and the injector's own, and no collector option.

    Scenario: The injector dev help lists the common and injector options
      Given the injectors SDK exposes the injector dev help
      When the injector dev help is read
      Then the help section "common options" lists exactly --dev, -h, --out, --record and --replay
      And the help section "injector options" lists exactly --inject, --timeout, --emit, --dump-contracts, --list-contracts and --new-inject
      And the help has no "collector options" section
    """
    helper = _given_injector_dev_help()
    text = _when_reading_the_help(helper)
    _then_help_groups(text, "common options", *COMMON_OPTIONS)
    _then_help_groups(text, "injector options", *INJECTOR_OPTIONS)
    _then_help_has_no_section(text, "collector options")


@pytest.mark.parametrize(
    ("argv", "timeout"),
    [(["--dev"], 600.0), (["--dev", "--timeout", "2.5"], 2.5)],
    ids=["default", "given"],
)
def test_the_wait_for_the_inject_to_complete_is_bounded(
    argv: list[str], timeout: float
) -> None:
    """It bounds the wait for the complete callback, 600 seconds unless given.

    Scenario Outline: The wait for the inject to complete is bounded
      Given the injectors SDK exposes the injector dev options
      And an injector command line with "<argv>"
      When the injector dev options are read
      Then the options wait <timeout> seconds for the inject to complete

      Examples:
        | argv                    | timeout |
        | --dev                   | 600     |
        | --dev --timeout 2.5     | 2.5     |
    """
    reader = _given_injector_dev_options_reader()
    options = _when_reading_dev_options(reader, argv)
    _then_options_are(options, timeout=timeout)
