"""injectors_sdk — OpenAEV Injectors SDK."""

__version__ = "0.1.0"

# Base injector lifecycle
# Daemon protocol (re-exported from xtm-oaev-sdk)
from xtm_oaev_sdk import DaemonProtocol

from injectors_sdk._core.base import (
    BaseInjector,
    ExecutionCallback,
    ExecutionStatus,
    InjectorConfig,
    InjectorContext,
)

# Errors
from injectors_sdk._core.engine.adapters.executor import SubprocessExecutor
from injectors_sdk._core.engine.adapters.parser import DefaultOutputParser

# Adapters (default implementations)
from injectors_sdk._core.engine.adapters.renderer import DefaultCommandRenderer
from injectors_sdk._core.engine.contracts.exec_policy import ExecPolicy

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

# Core engine
from injectors_sdk._core.engine.core.cli_engine import (
    SUCCESS_ANY,
    CliEngine,
    EngineResult,
)

# Factory
from injectors_sdk._core.engine.factory import create_cli_engine

# Ports (Protocol interfaces)
from injectors_sdk._core.engine.ports.protocols import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)
from injectors_sdk._core.errors import (
    BinaryNotFoundError,
    CliContractError,
    CliError,
    CliExecutionError,
    CliParseError,
    ExecResult,
)

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
