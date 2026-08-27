"""Focused parser and source-path edge cases."""

import json
from typing import Any, Callable

import pytest

from prowler._core.cli_engine import CommandResult, ExecutionSpecification
from prowler.models.findings import (
    OcsfDecodeError,
    OcsfMappingError,
    decode_ocsf_output,
    map_command_result,
    map_ocsf_finding,
)


def test_empty_json_array_and_blank_json_lines_are_empty() -> None:
    """Decode valid empty representations to an empty immutable collection."""
    assert decode_ocsf_output(b"[]") == ()
    assert decode_ocsf_output(b" \n\n\t") == ()


def test_single_json_line_object_is_accepted() -> None:
    """Accept one object as a one-record JSON Lines document."""
    assert decode_ocsf_output('{"finding_info": {}}') == ({"finding_info": {}},)


@pytest.mark.parametrize("payload", [b"null", b"42", b'"text"', b"{}\n[]"])
def test_top_level_or_jsonl_non_objects_are_rejected(payload: bytes) -> None:
    """Reject scalar top levels and non-object JSONL records."""
    with pytest.raises(OcsfDecodeError) as caught:
        decode_ocsf_output(payload)

    assert caught.value.code in {"invalid_top_level", "non_object_record"}


def test_command_result_must_be_success() -> None:
    """Reject a CHK.004 error envelope without exposing its details."""
    result = CommandResult(
        specification=ExecutionSpecification(
            executable="prowler",
            arguments=(),
            environment=(),
            working_directory=None,
            input_bytes=b"",
            output=object(),  # type: ignore[arg-type]
            timeout_seconds=1,
            maximum_accepted_output_bytes=1,
        ),
        return_code=1,
        error=RuntimeError("sensitive failure"),
    )

    with pytest.raises(OcsfMappingError) as caught:
        map_command_result(result)

    assert caught.value.code == "command_not_successful"
    assert "sensitive" not in str(caught.value)


@pytest.mark.parametrize(
    ("compliance", "expected"),
    [
        ({"A": "x", "B": ["y", "x"]}, ("x", "y", "x")),
        (["a", "b"], ("a", "b")),
        ("one", ("one",)),
        ({"A": {"first": "x", "second": ["y"]}}, ("x", "y")),
    ],
)
def test_supported_compliance_shapes_preserve_values_and_duplicates(
    copy_record: Callable[[], dict[str, Any]],
    compliance: object,
    expected: tuple[str, ...],
) -> None:
    """Flatten evidenced compliance forms in order without deduplication."""
    record = copy_record()
    record["unmapped"]["compliance"] = compliance

    assert map_ocsf_finding(record).compliance_tags == expected


def test_invalid_compliance_leaf_has_structured_error(
    copy_record: Callable[[], dict[str, Any]],
) -> None:
    """Report the exact unsupported compliance leaf path."""
    record = copy_record()
    record["unmapped"]["compliance"] = {"CIS": ["1.1", 42]}

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record, record_index=3)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.record_index == 3
    assert caught.value.source_path == "unmapped.compliance.CIS[1]"


@pytest.mark.parametrize(
    "path_mutation",
    [
        lambda record: record.update(finding_info="wrong"),
        lambda record: record.update(status=7),
        lambda record: record["resources"].__setitem__(0, "wrong"),
        lambda record: record["remediation"].update(references="wrong"),
    ],
)
def test_wrong_source_types_are_structured_errors(
    copy_record: Callable[[], dict[str, Any]],
    path_mutation: Callable[[dict[str, Any]], None],
) -> None:
    """Convert wrong source container and scalar types to safe errors."""
    record = copy_record()
    path_mutation(record)

    with pytest.raises(OcsfMappingError) as caught:
        map_ocsf_finding(record)

    assert caught.value.code == "invalid_source_value"
    assert caught.value.source_path
    assert json.dumps(record) not in str(caught.value)
