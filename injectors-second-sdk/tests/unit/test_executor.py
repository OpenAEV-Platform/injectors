"""RED tests for SubprocessExecutor."""

import pytest
from injectors_second_sdk import (
    BinaryNotFoundError,
    CliContractError,
    CliExecutionError,
    ExecPolicy,
    SubprocessExecutor,
)


@pytest.fixture
def executor() -> SubprocessExecutor:
    return SubprocessExecutor(ExecPolicy(timeout=5))


# --- Happy path ---


def test_executor_runs_echo(executor: SubprocessExecutor) -> None:
    result = executor.run(["echo", "hello"])
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_executor_captures_stderr(executor: SubprocessExecutor) -> None:
    result = executor.run(["sh", "-c", "echo error >&2"])
    assert "error" in result.stderr


def test_executor_captures_nonzero_returncode(executor: SubprocessExecutor) -> None:
    result = executor.run(["sh", "-c", "exit 42"])
    assert result.returncode == 42
    assert result.success is False


def test_executor_passes_env(executor: SubprocessExecutor) -> None:
    result = executor.run(["sh", "-c", "echo $TEST_VAR"], env={"TEST_VAR": "hello"})
    assert "hello" in result.stdout


def test_executor_respects_cwd(
    executor: SubprocessExecutor, tmp_path: pytest.TempPathFactory
) -> None:
    result = executor.run(["pwd"], cwd=str(tmp_path))
    assert str(tmp_path) in result.stdout


def test_executor_passes_stdin(executor: SubprocessExecutor) -> None:
    result = executor.run(["cat"], stdin="hello world")
    assert "hello world" in result.stdout


# --- Error cases ---


def test_executor_raises_on_timeout() -> None:
    short_timeout = SubprocessExecutor(ExecPolicy(timeout=1))
    with pytest.raises(CliExecutionError) as exc_info:
        short_timeout.run(["sleep", "10"])
    assert exc_info.value.result.returncode == 124


def test_executor_raises_binary_not_found() -> None:
    executor = SubprocessExecutor(ExecPolicy(check_binary_exists=True))
    with pytest.raises(BinaryNotFoundError, match="nonexistent_binary_xyz"):
        executor.run(["nonexistent_binary_xyz"])


def test_executor_raises_on_empty_argv(executor: SubprocessExecutor) -> None:
    with pytest.raises(CliContractError, match="must not be empty"):
        executor.run([])


def test_executor_raises_on_non_list_argv(executor: SubprocessExecutor) -> None:
    with pytest.raises(CliContractError, match="list of strings"):
        executor.run("echo hello")  # type: ignore[arg-type]


# --- Shell metachar safety ---


def test_executor_warns_on_metachars_no_shell(executor: SubprocessExecutor) -> None:
    with pytest.warns(UserWarning, match="metacharacters"):
        executor.run(["echo", "hello | world"])


def test_executor_rejects_metachars_with_shell() -> None:
    shell_executor = SubprocessExecutor(
        ExecPolicy(shell=True, acknowledge_shell_risk=True, timeout=5)
    )
    with pytest.raises(CliContractError, match="injection risk"):
        shell_executor.run(["echo", "hello | world"])


# --- Output truncation ---


def test_executor_truncates_output() -> None:
    executor = SubprocessExecutor(ExecPolicy(timeout=5, max_output_bytes=10))
    result = executor.run(["echo", "a very long string that exceeds the limit"])
    assert "[truncated]" in result.stdout
