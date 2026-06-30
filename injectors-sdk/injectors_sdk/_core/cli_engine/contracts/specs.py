"""Pydantic models defining CLI binary, command, option, argument, and output specs."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class OptionKind(StrEnum):
    """Supported option rendering modes.

    Attributes:
        BOOL: Flag-only (present or absent).
        VALUE: Flag followed by a value.
        LIST: Flag repeated for each value in a list.
    """

    BOOL = "bool"
    VALUE = "value"
    LIST = "list"


class OutputFormat(StrEnum):
    """Supported command output parsing formats.

    Attributes:
        TEXT: Return stdout as a plain string.
        JSON: Parse stdout as JSON.
        REGEX: Apply a regex pattern to stdout.
        LINES: Split stdout into lines.
        RAW: Return stdout bytes as-is.
    """

    TEXT = "text"
    JSON = "json"
    REGEX = "regex"
    LINES = "lines"
    RAW = "raw"


class OptionSpec(BaseModel):
    """Specification for one named CLI option.

    Attributes:
        name: Option identifier used in the options dict.
        flag: The CLI flag string (e.g., '-o', '--output').
        kind: Rendering mode (bool, value, or list).
        required: Whether this option must be provided.
        repeatable: Whether the option can appear multiple times.
        choices: Allowed values (None means any value accepted).
        equals: Use '=' syntax (e.g., --flag=value).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    flag: str
    kind: OptionKind = OptionKind.VALUE
    required: bool = False
    repeatable: bool = False
    choices: list[str] | None = None
    equals: bool = False


class ArgumentSpec(BaseModel):
    """Specification for one positional CLI argument.

    Attributes:
        name: Argument identifier used in the args dict.
        required: Whether this argument must be provided.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    required: bool = False


class OutputSpec(BaseModel):
    """Specification describing how stdout should be parsed.

    Attributes:
        format: The parsing format to apply.
        regex: Pattern string (required when format is REGEX).
    """

    model_config = ConfigDict(frozen=True)

    format: OutputFormat = OutputFormat.TEXT
    regex: str | None = None

    @model_validator(mode="after")
    def _regex_required_for_regex_format(self) -> "OutputSpec":
        if self.format == OutputFormat.REGEX and self.regex is None:
            raise ValueError("regex field is required when format is REGEX")
        return self


class CommandSpec(BaseModel):
    """Specification for one executable command.

    Attributes:
        name: Command identifier used for lookup.
        argv: Static arguments prepended to every invocation.
        options: Named option specifications.
        arguments: Positional argument specifications.
        output: How to parse command output.
        success_codes: Exit codes considered successful.
        allow_raw_args: Whether undeclared raw arguments are allowed.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    argv: list[str] = Field(default_factory=list)
    options: dict[str, OptionSpec] = Field(default_factory=dict)
    arguments: list[ArgumentSpec] = Field(default_factory=list)
    output: OutputSpec = Field(default_factory=OutputSpec)
    success_codes: set[int] = Field(default_factory=lambda: {0})
    allow_raw_args: bool = False

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, value: str) -> str:
        """Reject empty or whitespace-only command names."""
        if not value.strip():
            raise ValueError("command name cannot be empty")
        return value


class BinarySpec(BaseModel):
    """Specification for a binary and its available commands.

    Attributes:
        name: Human-readable binary identifier.
        binary: Executable name or path.
        commands: Available commands indexed by name.
        version_args: Arguments to retrieve the binary version.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    binary: str
    commands: dict[str, CommandSpec]
    version_args: list[str] = Field(default_factory=lambda: ["--version"])

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, value: str) -> str:
        """Reject empty or whitespace-only binary names."""
        if not value.strip():
            raise ValueError("binary name cannot be empty")
        return value

    @field_validator("binary")
    @classmethod
    def binary_must_not_be_empty(cls, value: str) -> str:
        """Reject empty or whitespace-only binary paths."""
        if not value.strip():
            raise ValueError("binary cannot be empty")
        return value

    @field_validator("commands", mode="after")
    @classmethod
    def commands_must_not_be_empty(
        cls, value: dict[str, "CommandSpec"]
    ) -> dict[str, "CommandSpec"]:
        """Reject empty commands dict."""
        if not value:
            raise ValueError("commands must include at least one command")
        return value

    @field_validator("commands", mode="before")
    @classmethod
    def normalize_commands(cls, value: object) -> object:
        """Allow commands to be provided as list[CommandSpec] or dict[name, CommandSpec]."""
        if isinstance(value, dict):
            return value
        if not isinstance(value, list):
            return value

        normalized: dict[str, dict[str, object] | CommandSpec] = {}
        for raw_command in value:
            command = (
                raw_command
                if isinstance(raw_command, CommandSpec)
                else CommandSpec.model_validate(raw_command)
            )
            if command.name in normalized:
                raise ValueError(f"duplicate command name: {command.name}")
            normalized[command.name] = command

        if not normalized:
            raise ValueError("commands must include at least one command")
        return normalized


__all__ = [
    "ArgumentSpec",
    "BinarySpec",
    "CommandSpec",
    "OptionKind",
    "OptionSpec",
    "OutputFormat",
    "OutputSpec",
]
