"""RED tests for DefaultOutputParser."""

import json

import pytest
from pydantic import BaseModel

from injectors_sdk import (
    CliContractError,
    CliParseError,
    DefaultOutputParser,
    ExecResult,
    OutputFormat,
    OutputSpec,
)


@pytest.fixture
def parser() -> DefaultOutputParser:
    return DefaultOutputParser()


def _given_result(stdout: str = "", returncode: int = 0) -> ExecResult:
    return ExecResult(argv=["test"], returncode=returncode, stdout=stdout, stderr="")


# --- TEXT format ---

def test_parse_text_returns_stdout(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="hello world")
    parsed = parser.parse(result, OutputSpec(format=OutputFormat.TEXT))
    assert parsed == "hello world"


def test_parse_text_rejects_model(parser: DefaultOutputParser) -> None:
    class M(BaseModel):
        x: int

    with pytest.raises(CliContractError, match="not supported"):
        parser.parse(_given_result(), OutputSpec(format=OutputFormat.TEXT), model=M)


# --- RAW format ---

def test_parse_raw_returns_stdout(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="raw bytes here")
    parsed = parser.parse(result, OutputSpec(format=OutputFormat.RAW))
    assert parsed == "raw bytes here"


# --- LINES format ---

def test_parse_lines_splits_by_newline(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="line1\nline2\nline3")
    parsed = parser.parse(result, OutputSpec(format=OutputFormat.LINES))
    assert parsed == ["line1", "line2", "line3"]


# --- JSON format ---

def test_parse_json_returns_dict(parser: DefaultOutputParser) -> None:
    data = {"key": "value", "count": 42}
    result = _given_result(stdout=json.dumps(data))
    parsed = parser.parse(result, OutputSpec(format=OutputFormat.JSON))
    assert parsed == data


def test_parse_json_with_model(parser: DefaultOutputParser) -> None:
    class Item(BaseModel):
        name: str
        count: int

    result = _given_result(stdout='{"name": "test", "count": 5}')
    parsed = parser.parse(result, OutputSpec(format=OutputFormat.JSON), model=Item)
    assert isinstance(parsed, Item)
    assert parsed.name == "test"
    assert parsed.count == 5


def test_parse_json_invalid_raises(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="not json")
    with pytest.raises(CliParseError, match="not valid JSON"):
        parser.parse(result, OutputSpec(format=OutputFormat.JSON))


def test_parse_json_model_mismatch_raises(parser: DefaultOutputParser) -> None:
    class Strict(BaseModel):
        required_field: int

    result = _given_result(stdout='{"other": "value"}')
    with pytest.raises(CliParseError, match="model contract"):
        parser.parse(result, OutputSpec(format=OutputFormat.JSON), model=Strict)


# --- REGEX format ---

def test_parse_regex_returns_groupdict(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="version 1.2.3")
    spec = OutputSpec(format=OutputFormat.REGEX, regex=r"version (?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)")
    parsed = parser.parse(result, spec)
    assert parsed == {"major": "1", "minor": "2", "patch": "3"}


def test_parse_regex_no_match_raises(parser: DefaultOutputParser) -> None:
    result = _given_result(stdout="no match here")
    spec = OutputSpec(format=OutputFormat.REGEX, regex=r"version (?P<v>\d+)")
    with pytest.raises(CliParseError, match="did not match"):
        parser.parse(result, spec)


def test_parse_regex_missing_pattern_raises(parser: DefaultOutputParser) -> None:
    from pydantic import ValidationError as PydanticValidationError

    result = _given_result(stdout="anything")
    with pytest.raises(PydanticValidationError, match="regex field is required"):
        OutputSpec(format=OutputFormat.REGEX)


def test_parse_regex_with_model(parser: DefaultOutputParser) -> None:
    class Version(BaseModel):
        major: int
        minor: int

    result = _given_result(stdout="v2.5")
    spec = OutputSpec(format=OutputFormat.REGEX, regex=r"v(?P<major>\d+)\.(?P<minor>\d+)")
    parsed = parser.parse(result, spec, model=Version)
    assert isinstance(parsed, Version)
    assert parsed.major == 2
    assert parsed.minor == 5
