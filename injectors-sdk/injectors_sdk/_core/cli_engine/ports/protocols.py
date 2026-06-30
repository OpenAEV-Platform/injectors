"""Port definitions (Protocol interfaces) for the CLI Engine."""

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from injectors_sdk._core.cli_engine.contracts.specs import CommandSpec, OutputSpec
from injectors_sdk._core.cli_engine.errors import ExecResult


@runtime_checkable
class CommandExecutorPort(Protocol):
    """Protocol for command execution implementations.

    Implementors execute a rendered argv list and return structured results.
    """

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdin: str | bytes | None = None,
    ) -> ExecResult: ...


@runtime_checkable
class CommandRendererPort(Protocol):
    """Protocol for pure command rendering implementations.

    Implementors produce an argv list from a binary name, command spec, and user inputs.
    """

    def render(
        self,
        binary: str,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
    ) -> list[str]: ...


@runtime_checkable
class OutputParserPort(Protocol):
    """Protocol for parsing command execution output.

    Implementors transform raw ExecResult stdout into structured data
    according to an OutputSpec.
    """

    def parse(
        self,
        result: ExecResult,
        output_spec: OutputSpec,
        model: type[BaseModel] | None = None,
        context: dict[str, object] | None = None,
    ) -> Any: ...


__all__ = [
    "CommandExecutorPort",
    "CommandRendererPort",
    "OutputParserPort",
]
