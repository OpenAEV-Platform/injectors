from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from injectors_sdk import (
    ArgumentSpec,
    BinarySpec,
    CommandSpec,
    ExecPolicy,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
)


def _given_option_spec(**kwargs: Any) -> OptionSpec:
    return OptionSpec(**kwargs)


def _given_argument_spec(**kwargs: Any) -> ArgumentSpec:
    return ArgumentSpec(**kwargs)


def _given_output_spec(**kwargs: Any) -> OutputSpec:
    return OutputSpec(**kwargs)


def _given_command_spec(**kwargs: Any) -> CommandSpec:
    return CommandSpec(**kwargs)


def _given_binary_spec(**kwargs: Any) -> BinarySpec:
    return BinarySpec(**kwargs)


def _given_exec_policy(**kwargs: Any) -> ExecPolicy:
    return ExecPolicy(**kwargs)


def _when_assigning_attribute(obj: object, attr: str, value: Any) -> None:
    setattr(obj, attr, value)


def _then_enum_values_are_complete() -> None:
    assert [member.value for member in OptionKind] == ["bool", "value", "list"]
    assert [member.value for member in OutputFormat] == ["text", "json", "regex", "lines", "raw"]


def _then_validation_error_is_raised(callable_obj: Any) -> None:
    with pytest.raises(ValidationError):
        callable_obj()


def test_option_kind_enum_completeness() -> None:
    _then_enum_values_are_complete()


def test_output_format_enum_completeness() -> None:
    _then_enum_values_are_complete()


def test_option_spec_defaults_and_immutability() -> None:
    option = _given_option_spec(name="verbose")

    assert option.kind is OptionKind.BOOL
    assert option.required is False
    assert option.default is None

    with pytest.raises(ValidationError):
        _when_assigning_attribute(option, "required", True)


def test_argument_spec_defaults_and_immutability() -> None:
    argument = _given_argument_spec(name="path")

    assert argument.required is True
    assert argument.default is None

    with pytest.raises(ValidationError):
        _when_assigning_attribute(argument, "required", False)


def test_output_spec_defaults_to_text_format() -> None:
    output = _given_output_spec()
    assert output.format is OutputFormat.TEXT


def test_output_spec_requires_regex_when_format_is_regex() -> None:
    _then_validation_error_is_raised(lambda: _given_output_spec(format=OutputFormat.REGEX))


def test_output_spec_accepts_regex_when_format_is_regex() -> None:
    output = _given_output_spec(format=OutputFormat.REGEX, regex=r"^ok$")
    assert output.format is OutputFormat.REGEX
    assert output.regex == r"^ok$"


def test_command_spec_rejects_empty_name() -> None:
    _then_validation_error_is_raised(lambda: _given_command_spec(name=""))


def test_command_spec_defaults_are_applied() -> None:
    command = _given_command_spec(name="status")
    assert command.name == "status"
    assert command.output.format is OutputFormat.TEXT
    assert command.options == {}
    assert command.arguments == []


def test_binary_spec_rejects_empty_name() -> None:
    _then_validation_error_is_raised(
        lambda: _given_binary_spec(name="", binary="my-cli", commands=[_given_command_spec(name="run")]),
    )


def test_binary_spec_rejects_empty_binary() -> None:
    _then_validation_error_is_raised(
        lambda: _given_binary_spec(name="tool", binary="", commands=[_given_command_spec(name="run")]),
    )


def test_binary_spec_rejects_empty_commands() -> None:
    _then_validation_error_is_raised(
        lambda: _given_binary_spec(name="tool", binary="tool", commands=[]),
    )


def test_binary_spec_normalizes_commands_list_to_dict() -> None:
    run = _given_command_spec(name="run")
    inspect = _given_command_spec(name="inspect")
    spec = _given_binary_spec(name="tool", binary="tool", commands=[run, inspect])

    assert set(spec.commands.keys()) == {"run", "inspect"}
    assert spec.commands["run"].name == "run"
    assert spec.commands["inspect"].name == "inspect"


def test_exec_policy_accepts_shell_boolean() -> None:
    policy = _given_exec_policy(shell=False, timeout=30)
    assert policy.shell is False


def test_exec_policy_accepts_shell_auto() -> None:
    policy = _given_exec_policy(shell="auto", timeout=30)
    assert policy.shell == "auto"


def test_exec_policy_rejects_invalid_shell_value() -> None:
    _then_validation_error_is_raised(lambda: _given_exec_policy(shell="yes", timeout=30))


def test_exec_policy_requires_ack_when_shell_true() -> None:
    _then_validation_error_is_raised(lambda: _given_exec_policy(shell=True, timeout=30))


def test_exec_policy_allows_shell_true_with_acknowledgement() -> None:
    policy = _given_exec_policy(shell=True, acknowledge_shell_risk=True, timeout=30)
    assert policy.shell is True
    assert policy.acknowledge_shell_risk is True


def test_exec_policy_rejects_timeout_less_than_one() -> None:
    _then_validation_error_is_raised(lambda: _given_exec_policy(shell=False, timeout=0))


def test_exec_policy_forbids_extra_fields() -> None:
    _then_validation_error_is_raised(
        lambda: ExecPolicy(shell=False, timeout=30, unexpected="value"),
    )
