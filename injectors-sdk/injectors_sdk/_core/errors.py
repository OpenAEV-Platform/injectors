"""Error hierarchy and execution result model for injectors-sdk."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class ExecResult:
    """Structured output from a CLI command execution.

    Attributes:
        argv: The command-line arguments that were executed.
        returncode: The process exit code.
        success_codes: Set of exit codes considered successful.
        stdout: Captured standard output.
        stderr: Captured standard error.
        success: Whether returncode is in success_codes (computed).
    """

    argv: list[str] = field(default_factory=list)
    returncode: int = 0
    success_codes: set[int] = field(default_factory=lambda: {0})
    stdout: str = ""
    stderr: str = ""
    success: bool = field(init=False)

    def __post_init__(self) -> None:
        self.success = self.returncode in self.success_codes


class CliError(Exception):
    """Base class for all injectors-sdk CLI errors."""


class CliContractError(CliError):
    """Raised when caller input violates the binary/command contract."""


class CliExecutionError(CliError):
    """Raised when command execution fails.

    Attributes:
        result: The ExecResult from the failed execution.
        returncode: The process exit code.
        stderr: Captured standard error output.
    """

    def __init__(self, result: ExecResult) -> None:
        self.result = result
        self.returncode = result.returncode
        self.stderr = result.stderr
        super().__init__(f"Command failed with returncode={result.returncode}: {result.stderr}")


class CliParseError(CliError):
    """Raised when command output cannot be parsed."""


class BinaryNotFoundError(CliExecutionError):
    """Raised when the target binary cannot be found on the system.

    Attributes:
        binary: The name/path of the binary that was not found.
    """

    def __init__(self, binary: str, result: ExecResult | None = None) -> None:
        self.binary = binary
        super().__init__(
            result
            or ExecResult(
                argv=[binary],
                returncode=127,
                stdout="",
                stderr=f"Binary not found: {binary}",
            )
        )


__all__ = [
    "BinaryNotFoundError",
    "CliContractError",
    "CliError",
    "CliExecutionError",
    "CliParseError",
    "ExecResult",
]
