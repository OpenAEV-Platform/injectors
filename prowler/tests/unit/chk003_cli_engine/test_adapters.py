"""Focused unit contract for CHK.003 production adapters."""

# ruff: noqa: D103

import importlib
import subprocess
from typing import Any
from unittest.mock import patch

import pytest


def _api() -> Any:
    try:
        return importlib.import_module("prowler._core.cli_engine")
    except ModuleNotFoundError:
        pytest.fail("canonical prowler._core.cli_engine API is absent")


def _spec(api: Any, **changes: Any) -> Any:
    values = {
        "executable": "tool",
        "arguments": ("a;b",),
        "environment": (("KEY", "value"),),
        "working_directory": "/work",
        "input_bytes": b"\x00\xff",
        "output": api.OutputSpecification(parser="raw"),
        "timeout_seconds": 2.5,
        "maximum_accepted_output_bytes": 100,
    }
    values.update(changes)
    return api.ExecutionSpecification(**values)


def test_subprocess_executor_forces_shell_false_and_preserves_bytes() -> (
    None
):  # noqa: D103
    api = _api()
    specification = _spec(api)
    completed = subprocess.CompletedProcess(
        args=specification.argv, returncode=0, stdout=b"\xff", stderr=b"\x00"
    )

    with patch("subprocess.run", return_value=completed) as run:
        outcome = api.SubprocessExecutor().execute(specification)

    run.assert_called_once_with(
        ("tool", "a;b"),
        input=b"\x00\xff",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/work",
        env={"KEY": "value"},
        timeout=2.5,
        shell=False,
        check=False,
    )
    assert outcome == api.ProcessOutcome(0, b"\xff", b"\x00")


def test_subprocess_start_and_timeout_errors_are_enveloped() -> None:  # noqa: D103
    api = _api()
    specification = _spec(api)
    executor = api.SubprocessExecutor()
    with patch("subprocess.run", side_effect=OSError("missing")):
        started = executor.execute(specification)
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(
            specification.argv, 2.5, output=b"partial\xff", stderr=b"slow\x00"
        ),
    ):
        timed_out = executor.execute(specification)

    assert started.kind == "process_start_failed"
    assert started.stdout == b"" and started.stderr == b""
    assert timed_out.kind == "timeout"
    assert (timed_out.stdout, timed_out.stderr) == (b"partial\xff", b"slow\x00")


def test_binary_resolver_only_validates_exact_executable() -> None:  # noqa: D103
    api = _api()
    specification = _spec(api, executable="scanner")
    resolver = api.WhichBinaryResolver()
    with patch("shutil.which", return_value="/different/scanner") as which:
        result = resolver.validate(specification)
    assert result is None
    which.assert_called_once_with("scanner", path="value" if False else None)
    assert specification.executable == "scanner"


@pytest.mark.parametrize(
    ("output", "specification", "expected"),
    [
        (b"\x00\xff", ("raw", None), b"\x00\xff"),
        (b"hello\n", ("text", None), "hello\n"),
        (b'{"ok": true}', ("json", None), {"ok": True}),
        (b"a\nb\n", ("lines", None), ["a", "b"]),
        (b"id=42", ("regex", r"id=(\d+)"), "42"),
    ],
)
def test_output_parsers(  # noqa: D103
    output: bytes, specification: tuple[str, str | None], expected: Any
) -> None:
    api = _api()
    spec = _spec(api, output=api.OutputSpecification(*specification))
    assert api.OutputParserAdapter().parse(spec, output) == expected


def test_parser_failure_has_safe_context_without_claiming_process_evidence() -> (
    None
):  # noqa: D103
    api = _api()
    spec = _spec(api, output=api.OutputSpecification(parser="json"))
    error = api.OutputParserAdapter().parse(spec, b"{bad")
    assert isinstance(error, api.ParsingError)
    assert error.stdout == b"" and error.stderr == b""
    assert error.context
