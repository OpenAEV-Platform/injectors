"""Canonical public API for safe local CLI execution."""

from .adapters import (OutputParserAdapter, SubprocessExecutor,
                       WhichBinaryResolver)
from .contracts import (CommandResult, ExecutionSpecification,
                        OutputSpecification, ProcessOutcome,
                        ValidatedCommandRequest)
from .engine import CliEngine
from .errors import (CliEngineError, ExecutionError, ParsingError, PolicyError,
                     ResolutionError)
from .factory import CliEngineFactory
from .policy import ExecutionPolicy
from .ports import (BinaryResolverPort, ExecutorPort, OutputParserPort,
                    PolicyPort)

__all__ = [
    "BinaryResolverPort",
    "CliEngine",
    "CliEngineError",
    "CliEngineFactory",
    "CommandResult",
    "ExecutionError",
    "ExecutionPolicy",
    "ExecutionSpecification",
    "ExecutorPort",
    "OutputParserAdapter",
    "OutputParserPort",
    "OutputSpecification",
    "ParsingError",
    "PolicyError",
    "PolicyPort",
    "ProcessOutcome",
    "ResolutionError",
    "SubprocessExecutor",
    "ValidatedCommandRequest",
    "WhichBinaryResolver",
]
