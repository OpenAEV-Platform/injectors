"""Unit tests for the structured subprocess adapter."""

import importlib
from typing import Any
from unittest.mock import patch

import pytest


def _api() -> Any:
    try:
        return importlib.import_module("prowler.cli_engine")
    except ModuleNotFoundError:
        pytest.fail("CHK.003 subprocess executor is absent")


def test_subprocess_adapter_forces_shell_false_and_preserves_bytes() -> None:
    """Invoke subprocess with structured values and no shell."""
    api = _api()
    specification = api.ExecutionSpecification(
        executable="tool",
        arguments=("a;b",),
        environment=(("KEY", "value"),),
        working_directory="/work",
        input_bytes=b"\x00\xff",
        parser="raw",
    )
    completed = __import__("subprocess").CompletedProcess(
        args=specification.argv, returncode=0, stdout=b"\xff", stderr=b"\x00"
    )

    with patch("subprocess.run", return_value=completed) as run:
        outcome = api.SubprocessExecutor().execute(specification)

    run.assert_called_once_with(
        ("tool", "a;b"),
        input=b"\x00\xff",
        stdout=-1,
        stderr=-1,
        cwd="/work",
        env={"KEY": "value"},
        shell=False,
        check=False,
    )
    assert outcome == api.ProcessOutcome(0, b"\xff", b"\x00")
