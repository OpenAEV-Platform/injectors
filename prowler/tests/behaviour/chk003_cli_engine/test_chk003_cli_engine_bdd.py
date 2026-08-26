"""Executable behaviour contract for the generic CHK.003 CLI engine."""

import importlib
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from .conftest import RecordingPorts


def _api() -> Any:
    try:
        return importlib.import_module("prowler.cli_engine")
    except ModuleNotFoundError:
        pytest.fail("CHK.003 generic CLI engine behaviour is absent")


def _request(api: Any, **changes: Any) -> Any:
    values = {
        "executable": "scanner",
        "arguments": ("--format", "json"),
        "environment": (("LANG", "C"),),
        "working_directory": "/work",
        "input_bytes": b"input",
        "parser": "json",
    }
    values.update(changes)
    return api.ValidatedCliRequest(**values)


def _engine(api: Any, ports: RecordingPorts) -> Any:
    return api.CliEngine(policy=ports, resolver=ports, executor=ports, parser=ports)


def test_execution_specification_is_deeply_immutable() -> None:
    """Copy nested mutable request values into immutable structures."""
    api = _api()
    arguments = ["--format", "json"]
    environment = {"LANG": "C"}
    request = api.ValidatedCliRequest(
        executable="scanner",
        arguments=arguments,
        environment=environment,
        working_directory="/work",
        input_bytes=b"input",
        parser="json",
    )
    specification = api.ExecutionSpecification.from_request(request)
    arguments.append("--changed")
    environment["LANG"] = "changed"

    assert specification.arguments == ("--format", "json")
    assert specification.environment == (("LANG", "C"),)
    with pytest.raises(FrozenInstanceError):
        specification.executable = "other"


def test_structured_arguments_keep_shell_metacharacters_inert(
    recording_ports: RecordingPorts,
) -> None:
    """Keep shell syntax as inert individual arguments."""
    api = _api()
    request = _request(api, arguments=("value; rm -rf /", "$(unsafe)", "a && b"))
    recording_ports.outcome = api.ProcessOutcome(0, b"ok", b"")

    _engine(api, recording_ports).run(request)

    assert recording_ports.invocation.argv == (
        "scanner",
        "value; rm -rf /",
        "$(unsafe)",
        "a && b",
    )
    assert not hasattr(recording_ports.invocation, "command")


def test_resolver_cannot_replace_policy_approved_specification(
    recording_ports: RecordingPorts,
) -> None:
    """Keep the exact policy-approved specification through execution."""
    api = _api()
    request = _request(api)
    replacement = api.ExecutionSpecification.from_request(
        _request(api, executable="unapproved", arguments=("--bypass",))
    )
    recording_ports.resolver_return = replacement
    recording_ports.outcome = api.ProcessOutcome(0, b"ok", b"")

    _engine(api, recording_ports).run(request)

    assert (
        recording_ports.policy_specification is recording_ports.resolution_specification
    )
    assert recording_ports.policy_specification is recording_ports.invocation
    assert recording_ports.invocation.executable == "scanner"
    assert recording_ports.invocation.arguments == ("--format", "json")


@pytest.mark.parametrize(
    ("allowed", "resolvable", "error_type", "events"),
    [
        (False, True, "PolicyError", ["policy"]),
        (True, False, "ResolutionError", ["policy", "resolution"]),
    ],
)
def test_failures_short_circuit_in_boundary_order(
    recording_ports: RecordingPorts,
    allowed: bool,
    resolvable: bool,
    error_type: str,
    events: list[str],
) -> None:
    """Stop at the first failed boundary in required order."""
    api = _api()
    recording_ports.allowed = allowed
    recording_ports.resolvable = resolvable
    request = _request(api)

    with pytest.raises(getattr(api, error_type)):
        _engine(api, recording_ports).run(request)

    assert recording_ports.events == events


def test_nonzero_outcome_retains_bytes_and_skips_parsing(
    recording_ports: RecordingPorts,
) -> None:
    """Retain failed process streams without invoking the parser."""
    api = _api()
    stdout = b"partial\x00\xff\n"
    stderr = b"failure\x80\r\n"
    recording_ports.outcome = api.ProcessOutcome(7, stdout, stderr)
    request = _request(api)

    with pytest.raises(api.ExecutionError) as caught:
        _engine(api, recording_ports).run(request)

    assert (caught.value.stdout, caught.value.stderr) == (stdout, stderr)
    assert recording_ports.events == ["policy", "resolution", "execution"]


def test_executor_exception_becomes_execution_error(
    recording_ports: RecordingPorts,
) -> None:
    """Translate process-start exceptions into execution errors."""
    api = _api()
    recording_ports.outcome = OSError("cannot start")
    request = _request(api)

    with pytest.raises(api.ExecutionError) as caught:
        _engine(api, recording_ports).run(request)

    assert caught.value.stdout == b""
    assert caught.value.stderr == b""


def test_parser_exception_retains_original_process_bytes(
    recording_ports: RecordingPorts,
) -> None:
    """Retain exact process streams when parsing raises."""
    api = _api()
    stdout = b"\xff\x00not-json\n"
    stderr = b"warning\x80"
    recording_ports.outcome = api.ProcessOutcome(0, stdout, stderr)
    recording_ports.parse_error = ValueError("invalid")
    request = _request(api)

    with pytest.raises(api.ParsingError) as caught:
        _engine(api, recording_ports).run(request)

    assert (caught.value.stdout, caught.value.stderr) == (stdout, stderr)
    assert recording_ports.parsed_payload == stdout


def test_parser_parsing_error_is_rebuilt_with_actual_process_bytes(
    recording_ports: RecordingPorts,
) -> None:
    """Replace parser-owned evidence while retaining its failure as the cause."""
    api = _api()
    stdout = b"actual stdout\x00\xff"
    stderr = b"actual stderr\x80"
    parser_error = api.ParsingError(
        "invalid provider output", stdout=b"forged", stderr=b""
    )
    recording_ports.outcome = api.ProcessOutcome(0, stdout, stderr)
    recording_ports.parse_error = parser_error

    with pytest.raises(api.ParsingError) as caught:
        _engine(api, recording_ports).run(_request(api))

    assert caught.value is not parser_error
    assert caught.value.message == "invalid provider output"
    assert (caught.value.stdout, caught.value.stderr) == (stdout, stderr)
    assert caught.value.__cause__ is parser_error


def test_success_preserves_all_bytes_and_returns_parsed_result(
    recording_ports: RecordingPorts,
) -> None:
    """Return parsed data with exact captured streams."""
    api = _api()
    payload = b"\x00\xffline1\r\nline2\n"
    stderr = b"\x80warning\x00"
    request = _request(api, input_bytes=payload)
    recording_ports.outcome = api.ProcessOutcome(0, payload, stderr)

    result = _engine(api, recording_ports).run(request)

    assert recording_ports.invocation.input_bytes == payload
    assert recording_ports.parsed_payload == payload
    assert result == api.ExecutionSuccess(
        parsed={"parser": "json", "size": len(payload)},
        stdout=payload,
        stderr=stderr,
    )
    assert recording_ports.events == ["policy", "resolution", "execution", "parsing"]


def test_empty_values_remain_structured(recording_ports: RecordingPorts) -> None:
    """Preserve valid empty boundaries without coercion."""
    api = _api()
    request = _request(
        api,
        arguments=(),
        environment=(),
        working_directory=None,
        input_bytes=b"",
    )
    recording_ports.outcome = api.ProcessOutcome(0, b"", b"")

    _engine(api, recording_ports).run(request)

    assert recording_ports.invocation == api.ExecutionSpecification(
        executable="scanner",
        arguments=(),
        environment=(),
        working_directory=None,
        input_bytes=b"",
        parser="json",
    )
