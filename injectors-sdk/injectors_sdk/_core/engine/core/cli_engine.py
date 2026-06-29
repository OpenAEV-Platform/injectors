"""CLI Engine core: orchestrator that composes renderer, executor, and parser."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from injectors_sdk._core.engine.adapters.executor import SubprocessExecutor
from injectors_sdk._core.engine.adapters.parser import DefaultOutputParser
from injectors_sdk._core.engine.adapters.renderer import DefaultCommandRenderer
from injectors_sdk._core.engine.contracts.exec_policy import ExecPolicy
from injectors_sdk._core.engine.contracts.specs import CommandSpec, OutputSpec
from injectors_sdk._core.engine.ports.protocols import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)
from injectors_sdk._core.errors import ExecResult

SUCCESS_ANY: frozenset[int] = frozenset({0})
"""Default success codes set: only 0 is considered success."""


@dataclass(frozen=True)
class EngineResult:
    """Immutable result of a CLI Engine execution.

    Attributes:
        parsed: The parsed output (type depends on OutputSpec format).
        raw: The raw ExecResult from the subprocess.
        success: Whether the command returncode was in the success set.
        argv: The rendered argv list that was executed.
    """

    parsed: Any
    raw: ExecResult
    success: bool
    argv: list[str] = field(default_factory=list)

    def pipe(
        self,
        engine: CliEngine,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
        output_spec: OutputSpec | None = None,
        output_model: type[BaseModel] | None = None,
        success_codes: frozenset[int] | None = None,
        stdin: str | bytes | None = None,
    ) -> EngineResult:
        """Chain this result's parsed output as stdin to another engine run.

        Enables fluent pipeline composition: `result.pipe(engine, cmd2)`.

        Args:
            engine: The CLI Engine to pipe into.
            command: The command spec for the next stage.
            options: Named option values.
            args: Named positional argument values.
            raw_args: Undeclared arguments passed through verbatim.
            output_spec: Output parsing specification.
            output_model: Optional Pydantic model for validation.
            success_codes: Success return code set.
            stdin: Explicit stdin (overrides piping parsed output).

        Returns:
            A new EngineResult from the piped execution.
        """
        pipe_stdin = stdin
        if pipe_stdin is None and self.parsed is not None:
            pipe_stdin = str(self.parsed) if not isinstance(self.parsed, str) else self.parsed

        return engine.run(
            command,
            options=options,
            args=args,
            raw_args=raw_args,
            output_spec=output_spec,
            output_model=output_model,
            success_codes=success_codes,
            stdin=pipe_stdin,
        )


class CliEngine:
    """Hexagonal CLI Engine composing renderer, executor, and parser.

    The engine orchestrates:
    1. Render the argv from a CommandSpec and user inputs.
    2. Execute the argv via the executor port.
    3. Parse the output via the parser port.

    Attributes:
        binary: The default binary name or path.
        policy: Execution policy for subprocess control.
        renderer: The command renderer implementation.
        executor: The command executor implementation.
        parser: The output parser implementation.
    """

    def __init__(
        self,
        binary: str,
        *,
        policy: ExecPolicy | None = None,
        renderer: CommandRendererPort | None = None,
        executor: CommandExecutorPort | None = None,
        parser: OutputParserPort | None = None,
        success_codes: frozenset[int] | None = None,
    ) -> None:
        self.binary = binary
        self.policy = policy or ExecPolicy()
        self.renderer: CommandRendererPort = renderer or DefaultCommandRenderer()
        self.executor: CommandExecutorPort = executor or SubprocessExecutor(self.policy)
        self.parser: OutputParserPort = parser or DefaultOutputParser()
        self.success_codes = success_codes or SUCCESS_ANY

    def run(
        self,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
        output_spec: OutputSpec | None = None,
        output_model: type[BaseModel] | None = None,
        success_codes: frozenset[int] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdin: str | bytes | None = None,
    ) -> EngineResult:
        """Execute a CLI command through the full render→execute→parse pipeline.

        Args:
            command: The command specification to execute.
            options: Named option values for the command.
            args: Named positional argument values.
            raw_args: Undeclared arguments passed verbatim.
            output_spec: Output parsing specification (defaults to raw text).
            output_model: Optional Pydantic model for output validation.
            success_codes: Return codes considered successful (overrides engine default).
            env: Per-call environment variable overrides.
            cwd: Working directory for this execution.
            stdin: Input to pass to the process stdin.

        Returns:
            An EngineResult containing parsed output, raw result, and success status.
        """
        codes = success_codes if success_codes is not None else self.success_codes

        argv = self.renderer.render(
            self.binary,
            command,
            options=options,
            args=args,
            raw_args=raw_args,
        )

        result = self.executor.run(argv, env=env, cwd=cwd, stdin=stdin)

        parsed: Any = result.stdout
        if output_spec is not None:
            parsed = self.parser.parse(result, output_spec, model=output_model)

        return EngineResult(
            parsed=parsed,
            raw=result,
            success=result.returncode in codes,
            argv=argv,
        )


__all__ = [
    "CliEngine",
    "EngineResult",
    "SUCCESS_ANY",
]
