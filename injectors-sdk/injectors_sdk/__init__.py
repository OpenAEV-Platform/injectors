"""injectors_sdk — OpenAEV Injectors SDK."""

__version__ = "0.1.0"

# Errors
from injectors_sdk._core.errors import (
    BinaryNotFoundError,
    CliContractError,
    CliError,
    CliExecutionError,
    CliParseError,
    ExecResult,
)

__all__ = [
    "BinaryNotFoundError",
    "CliContractError",
    "CliError",
    "CliExecutionError",
    "CliParseError",
    "ExecResult",
]
