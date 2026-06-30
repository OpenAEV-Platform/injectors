"""CLI Engine core: orchestrator that composes renderer, executor, and parser."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from injectors_sdk._core.cli_engine.adapters.executor import SubprocessExecutor
from injectors_sdk._core.cli_engine.adapters.parser import DefaultOutputParser
from injectors_sdk._core.cli_engine.adapters.renderer import DefaultCommandRenderer
from injectors_sdk._core.cli_engine.contracts.exec_policy import ExecPolicy
from injectors_sdk._core.cli_engine.contracts.specs import CommandSpec, OutputSpec
from injectors_sdk._core.cli_engine.ports.protocols import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)
from injectors_sdk._core.cli_engine.errors import CliExecutionError, ExecResult

SUCCESS_ANY: frozenset[int] = frozenset(range(256))
"""All exit codes 0-255 considered success (accept any outcome)."""


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
    ) -> EngineResult:
        """Chain this result's stdout as stdin to another engine run.

        Enables fluent pipeline composition: `result.pipe(engine, cmd2)`.
        """
        return engine.run(
            command,
            options=options,
            args=args,
            raw_args=raw_args,
            output_spec=output_spec,
            output_model=output_model,
            success_codes=success_codes,
            stdin=self.raw.stdout,
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
        self.renderer: CommandRendererPort = (
            renderer or DefaultCommandRenderer()
        )
        self.executor: CommandExecutorPort = (
            executor or SubprocessExecutor(self.policy)
        )
        self.parser: OutputParserPort = parser or DefaultOutputParser()
        self.success_codes = success_codes or frozenset({0})

    def render(
        self,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
    ) -> list[str]:
        """Render argv for a command without executing it (dry-run).

        Useful for previewing, logging, or debugging the exact command
        that would be executed.

        Args:
            command: The command specification to render.
            options: Named option values for the command.
            args: Named positional argument values.
            raw_args: Undeclared arguments passed verbatim.

        Returns:
            The rendered argv list ready for subprocess execution.
        """
        return self.renderer.render(
            self.binary,
            command,
            options=options,
            args=args,
            raw_args=raw_args,
        )

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
        output_file: str | None = None,
    ) -> EngineResult:
        """Execute a CLI command through the render->execute->parse pipeline.

        Raises CliExecutionError when the command's returncode is not in
        the active success_codes set.

        Args:
            command: The command specification to execute.
            options: Named option values for the command.
            args: Named positional argument values.
            raw_args: Undeclared arguments passed verbatim.
            output_spec: Output parsing specification (defaults to raw
                stdout passthrough).
            output_model: Optional Pydantic model for JSON/REGEX
                output validation.
            success_codes: Return codes considered successful (overrides
                engine default).
            env: Per-call environment variable overrides.
            cwd: Working directory for this execution.
            stdin: Input to pass to the process stdin.
            output_file: Path to a file whose content is merged into
                stdout before parsing. The file is deleted after read.

        Returns:
            An EngineResult with parsed output, raw result, and success.

        Raises:
            CliExecutionError: When returncode is not in success_codes.
        """
        codes = (
            success_codes if success_codes is not None else self.success_codes
        )

        argv = self.renderer.render(
            self.binary,
            command,
            options=options,
            args=args,
            raw_args=raw_args,
        )

        result = self.executor.run(argv, env=env, cwd=cwd, stdin=stdin)

        # Propagate success codes so ExecResult.success is accurate
        result.success_codes = set(codes)
        result.success = result.returncode in codes

        if not result.success:
            raise CliExecutionError(result)

        # Merge output file content into stdout before parsing
        if output_file is not None:
            result = self._merge_output_file(result, output_file)

        parsed: Any = result.stdout
        if output_spec is not None:
            parsed = self.parser.parse(
                result, output_spec, model=output_model
            )

        return EngineResult(
            parsed=parsed,
            raw=result,
            success=True,
            argv=argv,
        )

    @staticmethod
    def _merge_output_file(
        result: ExecResult, output_file: str
    ) -> ExecResult:
        """Read a file, merge its content into result.stdout, delete it."""
        try:
            with open(
                output_file, "r", encoding="utf-8", errors="replace"
            ) as f:
                file_content = f.read()
            if file_content.strip():
                result.stdout = (
                    result.stdout.rstrip("\n") + "\n" + file_content
                )
        except FileNotFoundError:
            pass
        finally:
            try:
                os.remove(output_file)
            except OSError:
                pass
        return result


__all__ = [
    "CliEngine",
    "EngineResult",
    "SUCCESS_ANY",
]
