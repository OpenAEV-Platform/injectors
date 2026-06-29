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

# Ports (Protocol interfaces)
from injectors_sdk._core.engine.ports.protocols import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)

# Adapters (default implementations)
from injectors_sdk._core.engine.adapters.renderer import DefaultCommandRenderer
from injectors_sdk._core.engine.adapters.executor import SubprocessExecutor
from injectors_sdk._core.engine.adapters.parser import DefaultOutputParser

# Core engine
from injectors_sdk._core.engine.core.cli_engine import (
    CliEngine,
    EngineResult,
    SUCCESS_ANY,
)

# Factory
from injectors_sdk._core.engine.factory import create_cli_engine

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
    # Ports
    "CommandExecutorPort",
    "CommandRendererPort",
    "OutputParserPort",
    # Adapters
    "DefaultCommandRenderer",
    "DefaultOutputParser",
    "SubprocessExecutor",
    # Core
    "CliEngine",
    "EngineResult",
    "SUCCESS_ANY",
    # Factory
    "create_cli_engine",
]

