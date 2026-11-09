"""Tests for the dev help of an injector.

Feature: Dev help of an injector
  Started with "--dev --help", an injector prints the dev options and what each one is
  for, then exits with code 0, before reaching the platform or running anything.
"""

import io
import sys
from typing import Any, NamedTuple
from unittest.mock import MagicMock, patch

import pytest
from injectors_sdk import OpenAEVConfigHelper, OpenAEVInjectorHelper
from xtm_oaev_sdk import Configuration


class Run(NamedTuple):
    exit_code: Any
    stdout: str
    client_built: bool


class _RecordingHelper(OpenAEVInjectorHelper):
    client_built = False

    def _create_default_api_client(self, config):
        _RecordingHelper.client_built = True
        return MagicMock()


def _given_injector_configuration() -> OpenAEVConfigHelper:
    """Given an injector configuration"""
    return OpenAEVConfigHelper.from_configuration_object(
        Configuration(
            config_hints={
                "injector_id": {"data": "4f1d-injector"},
                "injector_name": {"data": "Port scanner"},
                "injector_type": {"data": "openaev_port_scanner"},
                "injector_contracts": {"data": []},
                "injector_log_level": {"data": "info"},
                "injector_json_logging": {"data": False},
            }
        )
    )


def _when_starting(configuration: OpenAEVConfigHelper, *args: str) -> Run:
    """When the injector starts with "<args>" """
    stdout = io.StringIO()
    _RecordingHelper.client_built = False
    with (
        patch.object(sys, "argv", ["openaev-port-scanner", *args]),
        patch.object(sys, "stdout", stdout),
        patch("xtm_oaev_sdk.PingAlive.start"),
    ):
        try:
            _RecordingHelper(configuration, MagicMock())
            exit_code: Any = "the injector went on"
        except SystemExit as exit_:
            exit_code = exit_.code
    return Run(exit_code, stdout.getvalue(), _RecordingHelper.client_built)


def _then_dev_help_is_printed(run: Run) -> None:
    """Then the common and injector dev options are printed, each with what it is for"""
    for option in ("--inject", "--out", "--emit", "--list-contracts", "--new-inject"):
        assert option in run.stdout, f"Expected {option} in {run.stdout!r}"
    assert "--expectations" not in run.stdout, "Expected no collector option"


def _then_injector_goes_on(run: Run) -> None:
    """Then the injector goes on, printing no dev help"""
    assert run.exit_code == "the injector went on", f"Exited with {run.exit_code}"
    assert "common options" not in run.stdout


def _then_exits_with(run: Run, code: int) -> None:
    """Then the injector exits with code <code>"""
    assert run.exit_code == code, f"Expected exit code {code}, got {run.exit_code}"


def _then_platform_client_is_never_built(run: Run) -> None:
    """Then the platform client is never built"""
    assert run.client_built is False


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_dev_help_prints_the_dev_options_and_exits(flag: str) -> None:
    """It prints the dev options and exits with code 0, before reaching the platform.

    Scenario Outline: The dev help prints the dev options and exits
      Given an injector configuration
      When the injector starts with "--dev <flag>"
      Then the common and injector dev options are printed, each with what it is for
      And the injector exits with code 0
      And the platform client is never built

      Examples:
        | flag   |
        | --help |
        | -h     |
    """
    configuration = _given_injector_configuration()
    run = _when_starting(configuration, "--dev", flag)
    _then_dev_help_is_printed(run)
    _then_exits_with(run, 0)
    _then_platform_client_is_never_built(run)


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_without_dev_stays_the_injector_s_own(flag: str) -> None:
    """It leaves -h and --help to the injector when --dev is absent.

    Scenario Outline: Help without --dev stays the injector's own
      Given an injector configuration
      When the injector starts with "<flag>"
      Then the injector goes on, printing no dev help

      Examples:
        | flag   |
        | --help |
        | -h     |
    """
    configuration = _given_injector_configuration()
    run = _when_starting(configuration, flag)
    _then_injector_goes_on(run)
