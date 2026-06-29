from __future__ import annotations

from injectors_sdk import (
    BinaryNotFoundError,
    CliContractError,
    CliError,
    CliExecutionError,
    CliParseError,
    ExecResult,
)


def _given_exec_result(**kwargs: object) -> ExecResult:
    return ExecResult(**kwargs)


def _when_creating_exec_result(**kwargs: object) -> ExecResult:
    return _given_exec_result(**kwargs)


def _then_exec_result_has_defaults(result: ExecResult) -> None:
    assert result.argv == []
    assert result.returncode == 0
    assert result.success_codes == {0}
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.success is True


def _then_success_matches_return_code(result: ExecResult, expected: bool) -> None:
    assert result.success is expected


def _when_creating_cli_execution_error(result: ExecResult) -> CliExecutionError:
    return CliExecutionError(result)


def _then_execution_error_carries_result(error: CliExecutionError, result: ExecResult) -> None:
    assert error.result is result
    assert error.returncode == result.returncode
    assert error.stderr == result.stderr


def _when_creating_binary_not_found_error(
    binary: str,
    result: ExecResult | None = None,
) -> BinaryNotFoundError:
    if result is None:
        return BinaryNotFoundError(binary)
    return BinaryNotFoundError(binary, result=result)


def _then_binary_not_found_error_has_default_result(
    error: BinaryNotFoundError, binary: str
) -> None:
    assert error.binary == binary
    assert isinstance(error.result, ExecResult)
    assert error.returncode == 127


def _then_binary_not_found_error_uses_custom_result(
    error: BinaryNotFoundError,
    expected_result: ExecResult,
) -> None:
    assert error.result is expected_result
    assert error.returncode == expected_result.returncode
    assert error.stderr == expected_result.stderr


def test_exec_result_defaults_computed_success() -> None:
    result = _when_creating_exec_result()
    _then_exec_result_has_defaults(result)


def test_exec_result_success_with_custom_success_codes() -> None:
    result = _when_creating_exec_result(returncode=2, success_codes={0, 2})
    _then_success_matches_return_code(result, expected=True)


def test_exec_result_success_false_when_returncode_not_in_codes() -> None:
    result = _when_creating_exec_result(returncode=5, success_codes={0, 2})
    _then_success_matches_return_code(result, expected=False)


def test_error_hierarchy_isinstance_checks() -> None:
    base = CliError("base")
    contract = CliContractError("contract")
    parse = CliParseError("parse")
    execution = CliExecutionError(_given_exec_result(returncode=1, stderr="boom"))
    missing_binary = BinaryNotFoundError("ffmpeg")

    assert isinstance(base, Exception)
    assert isinstance(contract, CliError)
    assert isinstance(parse, CliError)
    assert isinstance(execution, CliError)
    assert isinstance(missing_binary, CliExecutionError)
    assert isinstance(missing_binary, CliError)


def test_cli_execution_error_carries_result_data() -> None:
    result = _given_exec_result(returncode=9, stderr="permission denied")
    error = _when_creating_cli_execution_error(result)
    _then_execution_error_carries_result(error, result)


def test_binary_not_found_error_creates_default_result() -> None:
    error = _when_creating_binary_not_found_error(binary="missing-cli")
    _then_binary_not_found_error_has_default_result(error, binary="missing-cli")


def test_binary_not_found_error_accepts_custom_result() -> None:
    result = _given_exec_result(returncode=126, stderr="not executable")
    error = _when_creating_binary_not_found_error(binary="python3", result=result)
    _then_binary_not_found_error_uses_custom_result(error, expected_result=result)
