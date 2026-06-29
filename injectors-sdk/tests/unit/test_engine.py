"""RED tests for CliEngine and EngineResult integration."""

import pytest

from injectors_sdk import (
    CliEngine,
    CliContractError,
    CommandSpec,
    EngineResult,
    ExecPolicy,
    ExecResult,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
    SUCCESS_ANY,
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

def test_success_any_contains_zero() -> None:
    assert 0 in SUCCESS_ANY
    assert 1 not in SUCCESS_ANY


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


def test_engine_run_nonzero_is_failure() -> None:
    engine = create_cli_engine("sh", policy=ExecPolicy(timeout=5))
    cmd = CommandSpec(name="fail", argv=["-c", "exit 1"])
    result = engine.run(cmd)

    assert result.success is False
    assert result.raw.returncode == 1


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
    first_cmd = CommandSpec(name="echo", argv=[])

    # Run echo first, then pipe to cat
    echo_engine = create_cli_engine("echo", policy=ExecPolicy(timeout=5))
    first_result = echo_engine.run(CommandSpec(name="hello", argv=["piped_data"]))

    second_result = first_result.pipe(
        engine,
        CommandSpec(name="cat", argv=[]),
    )
    assert "piped_data" in second_result.raw.stdout


# --- Public API contract ---

def test_all_24_symbols_exported() -> None:
    import injectors_sdk
    assert len(injectors_sdk.__all__) == 24


def test_all_symbols_importable() -> None:
    import injectors_sdk
    for symbol in injectors_sdk.__all__:
        obj = getattr(injectors_sdk, symbol)
        assert obj is not None, f"{symbol} resolved to None"
