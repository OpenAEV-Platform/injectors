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

# Contracts
from injectors_sdk._core.engine.contracts.specs import (
    ArgumentSpec,
    BinarySpec,
    CommandSpec,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
)
from injectors_sdk._core.engine.contracts.exec_policy import ExecPolicy

__all__ = [
    # Errors
    "BinaryNotFoundError",
    "CliContractError",
    "CliError",
    "CliExecutionError",
    "CliParseError",
    "ExecResult",
    # Contracts
    "ArgumentSpec",
    "BinarySpec",
    "CommandSpec",
    "ExecPolicy",
    "OptionKind",
    "OptionSpec",
    "OutputFormat",
    "OutputSpec",
]
