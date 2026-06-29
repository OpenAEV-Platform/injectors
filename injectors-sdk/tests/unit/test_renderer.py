"""RED tests for DefaultCommandRenderer."""

import pytest
from injectors_sdk import (
    ArgumentSpec,
    CliContractError,
    CommandSpec,
    DefaultCommandRenderer,
    OptionKind,
    OptionSpec,
)


@pytest.fixture
def renderer() -> DefaultCommandRenderer:
    return DefaultCommandRenderer()


# --- GIVEN helpers ---


def _given_simple_command() -> CommandSpec:
    return CommandSpec(name="status", argv=["status"])


def _given_command_with_options() -> CommandSpec:
    return CommandSpec(
        name="commit",
        argv=["commit"],
        options={
            "message": OptionSpec(name="message", flag="-m", kind=OptionKind.VALUE),
            "all": OptionSpec(name="all", flag="--all", kind=OptionKind.BOOL),
            "verbose": OptionSpec(name="verbose", flag="-v", kind=OptionKind.BOOL),
        },
    )


def _given_command_with_arguments() -> CommandSpec:
    return CommandSpec(
        name="clone",
        argv=["clone"],
        arguments=[
            ArgumentSpec(name="url", required=True),
            ArgumentSpec(name="dest", required=False),
        ],
    )


def _given_command_with_list_option() -> CommandSpec:
    return CommandSpec(
        name="tag",
        argv=["tag"],
        options={
            "labels": OptionSpec(name="labels", flag="--label", kind=OptionKind.LIST),
        },
    )


def _given_command_with_choices() -> CommandSpec:
    return CommandSpec(
        name="log",
        argv=["log"],
        options={
            "format": OptionSpec(
                name="format",
                flag="--format",
                kind=OptionKind.VALUE,
                choices=["oneline", "short", "full"],
            ),
        },
    )


def _given_command_with_equals() -> CommandSpec:
    return CommandSpec(
        name="config",
        argv=["config"],
        options={
            "type": OptionSpec(name="type", flag="--type", kind=OptionKind.VALUE, equals=True),
        },
    )


def _given_command_allowing_raw_args() -> CommandSpec:
    return CommandSpec(name="run", argv=["run"], allow_raw_args=True)


# --- THEN: basic rendering ---


def test_render_simple_command(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render("git", _given_simple_command())
    assert argv == ["git", "status"]


def test_render_with_bool_option_true(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_options(),
        options={"all": True},
    )
    assert "--all" in argv


def test_render_with_bool_option_false(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_options(),
        options={"all": False},
    )
    assert "--all" not in argv


def test_render_with_value_option(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_options(),
        options={"message": "initial commit"},
    )
    assert "-m" in argv
    idx = argv.index("-m")
    assert argv[idx + 1] == "initial commit"


def test_render_with_list_option(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_list_option(),
        options={"labels": ["bug", "fix"]},
    )
    assert argv.count("--label") == 2


def test_render_with_equals_option(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_equals(),
        options={"type": "bool"},
    )
    assert "--type=bool" in argv


def test_render_positional_arguments(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "git",
        _given_command_with_arguments(),
        args={"url": "https://example.com/repo.git"},
    )
    assert argv == ["git", "clone", "https://example.com/repo.git"]


def test_render_raw_args_when_allowed(renderer: DefaultCommandRenderer) -> None:
    argv = renderer.render(
        "docker",
        _given_command_allowing_raw_args(),
        raw_args=["--rm", "-it", "ubuntu"],
    )
    assert "--rm" in argv
    assert "-it" in argv
    assert "ubuntu" in argv


# --- THEN: error cases ---


def test_render_unknown_option_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="Unknown option"):
        renderer.render(
            "git",
            _given_simple_command(),
            options={"nonexistent": "value"},
        )


def test_render_unknown_argument_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="Unknown argument"):
        renderer.render(
            "git",
            _given_command_with_arguments(),
            args={"nonexistent": "value"},
        )


def test_render_missing_required_option_raises(renderer: DefaultCommandRenderer) -> None:
    cmd = CommandSpec(
        name="test",
        argv=["test"],
        options={
            "required_opt": OptionSpec(
                name="required_opt", flag="--req", kind=OptionKind.VALUE, required=True
            ),
        },
    )
    with pytest.raises(CliContractError, match="Missing required option"):
        renderer.render("tool", cmd)


def test_render_missing_required_argument_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="Missing argument"):
        renderer.render("git", _given_command_with_arguments(), args={})


def test_render_raw_args_when_disallowed_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="does not accept undeclared"):
        renderer.render(
            "git",
            _given_simple_command(),
            raw_args=["--extra"],
        )


def test_render_invalid_choice_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="must be one of"):
        renderer.render(
            "git",
            _given_command_with_choices(),
            options={"format": "invalid"},
        )


def test_render_bool_option_with_non_bool_value_raises(renderer: DefaultCommandRenderer) -> None:
    with pytest.raises(CliContractError, match="must be a boolean"):
        renderer.render(
            "git",
            _given_command_with_options(),
            options={"all": "yes"},
        )
