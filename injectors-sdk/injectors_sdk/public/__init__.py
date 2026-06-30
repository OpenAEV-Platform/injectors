"""Public API — flat re-export of all 30 user-facing symbols."""

from xtm_oaev_sdk import DaemonProtocol

# Base injector lifecycle
from injectors_sdk._core.base_injector import (
    BaseInjector,
    ExecutionCallback,
    ExecutionStatus,
    InjectorConfig,
    InjectorContext,
)

# Errors
from injectors_sdk._core.cli_engine.errors import (
    BinaryNotFoundError,
    CliContractError,
    CliError,
    CliExecutionError,
    CliParseError,
    ExecResult,
)

# Contracts (specs + policy)
from injectors_sdk._core.cli_engine.contracts import (
    ArgumentSpec,
    BinarySpec,
    CommandSpec,
    ExecPolicy,
    OptionKind,
    OptionSpec,
    OutputFormat,
    OutputSpec,
)

# Ports
from injectors_sdk._core.cli_engine.ports import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)

# Adapters
from injectors_sdk._core.cli_engine.adapters import (
    DefaultCommandRenderer,
    DefaultOutputParser,
    SubprocessExecutor,
)

# Core engine
from injectors_sdk._core.cli_engine.core import (
    CliEngine,
    EngineResult,
    SUCCESS_ANY,
)

# Factory
from injectors_sdk._core.cli_engine.factory import create_cli_engine

__all__ = [
    # Base injector lifecycle
    "BaseInjector",
    "DaemonProtocol",
    "ExecutionCallback",
    "ExecutionStatus",
    "InjectorConfig",
    "InjectorContext",
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
