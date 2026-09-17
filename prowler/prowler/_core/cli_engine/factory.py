"""Composition root for production and injected CLI engines."""

from dataclasses import dataclass

from .adapters import (OutputParserAdapter, SubprocessExecutor,
                       WhichBinaryResolver)
from .engine import CliEngine
from .policy import ExecutionPolicy
from .ports import (BinaryResolverPort, ExecutorPort, OutputParserPort,
                    PolicyPort)


@dataclass(frozen=True)
class CliEngineFactory:
    """Construct an engine from explicit ports or safe defaults."""

    policy: PolicyPort = ExecutionPolicy()
    resolver: BinaryResolverPort = WhichBinaryResolver()
    executor: ExecutorPort = SubprocessExecutor()
    parser: OutputParserPort = OutputParserAdapter()

    def create(self) -> CliEngine:
        """Assemble a CLI engine."""
        return CliEngine(
            policy=self.policy,
            resolver=self.resolver,
            executor=self.executor,
            parser=self.parser,
        )
