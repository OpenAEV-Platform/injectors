"""Executable behaviour contract for CHK.003."""

import importlib
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from .conftest import RecordingPorts


def _api() -> Any:
    try:
        return importlib.import_module("prowler._core.cli_engine")
    except ModuleNotFoundError:
        pytest.fail("canonical prowler._core.cli_engine API is absent")


def _request(api: Any, **changes: Any) -> Any:
    values = {
        "executable": "scanner",
        "arguments": ["--format", "json"],
        "environment": {"LANG": "C"},
        "working_directory": "/work",
        "input_bytes": b"input",
        "output": api.OutputSpecification(parser="json"),
        "timeout_seconds": 30.0,
        "maximum_accepted_output_bytes": 4096,
    }
    values.update(changes)
    return api.ValidatedCommandRequest(**values)


def _engine(api: Any, ports: RecordingPorts) -> Any:
    return api.CliEngine(policy=ports, resolver=ports, executor=ports, parser=ports)


def test_specification_is_deeply_immutable() -> None:
    api = _api()
    arguments = ["--format", "json"]
    environment = {"LANG": "C"}
    output = api.OutputSpecification(parser="regex", pattern=r"id=(\d+)")
    request = _request(api, arguments=arguments, environment=environment, output=output)

    specification = api.ExecutionSpecification.from_request(request)
    arguments.append("changed")
    environment["LANG"] = "changed"

    assert specification.argv == ("scanner", "--format", "json")
    assert specification.environment == (("LANG", "C"),)
    assert specification.output == output
    with pytest.raises(FrozenInstanceError):
        specification.executable = "other"


def test_metacharacters_are_inert_structured_arguments(recording_ports: RecordingPorts) -> None:
    api = _api()
    recording_ports.execution_result = api.ProcessOutcome(0, b"ok", b"")
    request = _request(api, arguments=["a; rm -rf /", "$(touch nope)", "x && y"])

    _engine(api, recording_ports).run(request)

    assert recording_ports.seen[2].argv == (
        "scanner",
        "a; rm -rf /",
        "$(touch nope)",
        "x && y",
    )
    assert not hasattr(recording_ports.seen[2], "shell")


def test_same_exact_specification_crosses_all_boundaries(recording_ports: RecordingPorts) -> None:
    api = _api()
    recording_ports.execution_result = api.ProcessOutcome(0, b"ok", b"")

    result = _engine(api, recording_ports).run(_request(api))

    assert recording_ports.events == ["policy", "resolution", "execution", "parsing"]
    assert len({id(value) for value in recording_ports.seen}) == 1
    assert result.specification is recording_ports.seen[0]


@pytest.mark.parametrize(
    ("boundary", "error_name", "events"),
    [
        ("policy", "PolicyError", ["policy"]),
        ("resolution", "ResolutionError", ["policy", "resolution"]),
        ("execution", "ExecutionError", ["policy", "resolution", "execution"]),
        ("parsing", "ParsingError", ["policy", "resolution", "execution", "parsing"]),
    ],
)
def test_expected_failures_use_result_envelope(
    recording_ports: RecordingPorts, boundary: str, error_name: str, events: list[str]
) -> None:
    api = _api()
    error_type = getattr(api, error_name)
    error = error_type(message=f"{boundary} failed")
    recording_ports.execution_result = api.ProcessOutcome(0, b"output", b"warning")
    setattr(recording_ports, f"{boundary}_error" if boundary != "parsing" else "parsing_result", error)
    if boundary == "execution":
        recording_ports.execution_result = error

    result = _engine(api, recording_ports).run(_request(api))

    assert isinstance(result.error, error_type)
    assert recording_ports.events == events


def test_unsuccessful_outcome_retains_exact_bytes_and_skips_parser(
    recording_ports: RecordingPorts,
) -> None:
    api = _api()
    stdout = b"partial\x00\xff\n"
    stderr = b"failure\x80\r\n"
    recording_ports.execution_result = api.ProcessOutcome(17, stdout, stderr)

    result = _engine(api, recording_ports).run(_request(api))

    assert result.stdout == stdout and result.stderr == stderr
    assert result.error == api.ExecutionError(
        message="process returned an unsuccessful outcome",
        kind="unsuccessful_process",
        stdout=stdout,
        stderr=stderr,
        return_code=17,
    )
    assert recording_ports.events == ["policy", "resolution", "execution"]


def test_engine_replaces_parser_owned_evidence_and_preserves_context(
    recording_ports: RecordingPorts,
) -> None:
    api = _api()
    stdout, stderr = b"actual\x00\xff", b"warning\x80\n"
    recording_ports.execution_result = api.ProcessOutcome(0, stdout, stderr)
    recording_ports.parsing_result = api.ParsingError(
        message="invalid document",
        stdout=b"forged",
        stderr=b"forged",
        context=(("line", "7"),),
        cause="JSONDecodeError",
    )

    result = _engine(api, recording_ports).run(_request(api))

    assert result.error == api.ParsingError(
        message="invalid document",
        stdout=stdout,
        stderr=stderr,
        context=(("line", "7"),),
        cause="JSONDecodeError",
    )


def test_post_capture_output_size_classification_is_honest(
    recording_ports: RecordingPorts,
) -> None:
    api = _api()
    payload = b"x" * 5
    recording_ports.execution_result = api.ProcessOutcome(0, payload, b"err")

    result = _engine(api, recording_ports).run(
        _request(api, maximum_accepted_output_bytes=4)
    )

    assert result.error.kind == "output_too_large_after_capture"
    assert result.stdout == payload and result.error.stdout == payload
    assert recording_ports.events == ["policy", "resolution", "execution"]


def test_arbitrary_bytes_remain_exact(recording_ports: RecordingPorts) -> None:
    api = _api()
    payload, stderr = b"\x00\xffline\n", b"\x80warn\r\n"
    recording_ports.execution_result = api.ProcessOutcome(0, payload, stderr)
    recording_ports.parsing_result = payload

    result = _engine(api, recording_ports).run(
        _request(api, input_bytes=payload, output=api.OutputSpecification(parser="raw"))
    )

    assert recording_ports.seen[2].input_bytes == payload
    assert (result.parsed, result.stdout, result.stderr) == (payload, payload, stderr)


def test_only_core_package_is_public() -> None:
    api = _api()
    assert api.CliEngine
    for obsolete in ("prowler.cli_engine", "prowler.cli_engine_errors"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(obsolete)
