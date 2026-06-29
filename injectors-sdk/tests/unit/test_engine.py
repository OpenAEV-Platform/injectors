"""RED tests for CliEngine and EngineResult integration."""

import pytest
from injectors_sdk import (
    SUCCESS_ANY,
    CliEngine,
    CommandSpec,
    EngineResult,
    ExecPolicy,
    ExecResult,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
    create_cli_engine,
)

# --- Factory ---


def test_create_cli_engine_returns_engine() -> None:
    engine = create_cli_engine("echo")
    assert isinstance(engine, CliEngine)
    assert engine.binary == "echo"


def test_create_cli_engine_with_custom_policy() -> None:
    policy = ExecPolicy(timeout=120)
    engine = create_cli_engine("git", policy=policy)
    assert engine.policy.timeout == 120


# --- SUCCESS_ANY ---


def test_success_any_contains_all_codes() -> None:
    assert 0 in SUCCESS_ANY
    assert 1 in SUCCESS_ANY
    assert 127 in SUCCESS_ANY
    assert 255 in SUCCESS_ANY
    assert len(SUCCESS_ANY) == 256


# --- CliEngine.run ---


def test_engine_run_simple_echo() -> None:
    engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="hello", argv=["hello", "world"])
    result = engine.run(cmd)

    assert result.success is True
    assert "hello world" in result.raw.stdout
    assert result.argv[0] == "echo"


def test_engine_run_with_output_spec_json() -> None:
    engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="json", argv=['{"key": "value"}'])
    result = engine.run(cmd, output_spec=OutputSpec(format=OutputFormat.JSON))

    assert result.parsed == {"key": "value"}


def test_engine_run_nonzero_raises_cli_execution_error() -> None:
    from injectors_sdk import CliExecutionError

    engine = create_cli_engine("sh", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="fail", argv=["-c", "exit 1"])

    with pytest.raises(CliExecutionError) as exc_info:
        engine.run(cmd)

    assert exc_info.value.returncode == 1


def test_engine_run_custom_success_codes() -> None:
    engine = create_cli_engine("sh", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="diff", argv=["-c", "exit 1"])
    result = engine.run(cmd, success_codes=frozenset({0, 1}))

    assert result.success is True


def test_engine_run_with_options() -> None:
    engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(
        name="opts",
        argv=[],
        options={
            "msg": OptionSpec(name="msg", flag="--msg", kind=OptionKind.VALUE),
        },
    )
    result = engine.run(cmd, options={"msg": "hello"})
    assert "--msg" in result.argv
    assert "hello" in result.argv


# --- EngineResult ---


def test_engine_result_is_frozen() -> None:
    result = EngineResult(
        parsed="test",
        raw=ExecResult(argv=["test"], returncode=0, stdout="test", stderr=""),
        success=True,
        argv=["test"],
    )
    with pytest.raises(Exception):
        result.success = False  # type: ignore[misc]


def test_engine_result_pipe() -> None:
    engine = create_cli_engine("cat", policy=ExecPolicy(timeout=5))

    # Run echo first, then pipe to cat
    echo_engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    first_result = echo_engine.run(CommandSpec(name="hello", argv=["piped_data"]))

    second_result = first_result.pipe(
        engine,
        CommandSpec(name="cat", argv=[]),
    )
    assert "piped_data" in second_result.raw.stdout


# --- CliEngine.render (dry-run) ---


def test_engine_render_returns_argv_without_executing() -> None:
    engine = create_cli_engine("git", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(
        name="status",
        argv=["status"],
        options={
            "short": OptionSpec(name="short", flag="-s", kind=OptionKind.BOOL),
        },
    )
    argv = engine.render(cmd, options={"short": True})
    assert argv == ["git", "status", "-s"]


# --- output_file merge ---


def test_engine_run_merges_output_file(tmp_path: pytest.TempPathFactory) -> None:
    output_path = str(tmp_path / "out.txt")  # type: ignore[operator]
    with open(output_path, "w") as f:
        f.write("file_content_here")

    engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="echo", argv=["hello"])
    result = engine.run(cmd, output_file=output_path)

    assert "file_content_here" in result.raw.stdout
    import os

    assert not os.path.exists(output_path)


def test_engine_run_output_file_missing_is_not_error() -> None:
    engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="echo", argv=["hello"])
    result = engine.run(cmd, output_file="/nonexistent/path/out.txt")

    assert result.success is True


# --- auto-raise behavior ---


def test_engine_run_auto_raises_on_failure() -> None:
    from injectors_sdk import CliExecutionError

    engine = create_cli_engine("sh", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="fail", argv=["-c", "exit 42"])

    with pytest.raises(CliExecutionError) as exc_info:
        engine.run(cmd)

    assert exc_info.value.returncode == 42
    assert exc_info.value.result.returncode == 42


def test_engine_run_success_codes_suppresses_raise() -> None:
    engine = create_cli_engine("sh", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="diff", argv=["-c", "exit 42"])
    result = engine.run(cmd, success_codes=frozenset({0, 42}))

    assert result.success is True
    assert result.raw.returncode == 42


# --- Public API contract ---


def test_all_30_symbols_exported() -> None:
    import injectors_sdk

    assert len(injectors_sdk.__all__) == 30


def test_all_symbols_importable() -> None:
    import injectors_sdk

    for symbol in injectors_sdk.__all__:
        obj = getattr(injectors_sdk, symbol)
        assert obj is not None, f"{symbol} resolved to None"
