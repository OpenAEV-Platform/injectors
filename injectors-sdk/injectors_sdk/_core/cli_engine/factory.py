"""Factory for creating pre-configured CLI Engine instances."""

from injectors_sdk._core.cli_engine.adapters.executor import SubprocessExecutor
from injectors_sdk._core.cli_engine.adapters.parser import DefaultOutputParser
from injectors_sdk._core.cli_engine.adapters.renderer import DefaultCommandRenderer
from injectors_sdk._core.cli_engine.contracts.exec_policy import ExecPolicy
from injectors_sdk._core.cli_engine.core.cli_engine import CliEngine
from injectors_sdk._core.cli_engine.ports.protocols import (
    CommandExecutorPort,
    CommandRendererPort,
    OutputParserPort,
)


def create_cli_engine(
    binary: str,
    *,
    policy: ExecPolicy | None = None,
    renderer: CommandRendererPort | None = None,
    executor: CommandExecutorPort | None = None,
    parser: OutputParserPort | None = None,
    success_codes: frozenset[int] | None = None,
) -> CliEngine:
    """Create a fully-configured CLI Engine instance.

    This is the recommended entry point for constructing engines.
    Uses default adapter implementations when custom ports are not provided.

    Args:
        binary: The default binary name or path for this engine.
        policy: Execution policy controlling timeout, env, shell behavior.
        renderer: Custom command renderer (defaults to DefaultCommandRenderer).
        executor: Custom executor (defaults to SubprocessExecutor with policy).
        parser: Custom output parser (defaults to DefaultOutputParser).
        success_codes: Set of return codes considered successful.

    Returns:
        A configured CliEngine instance ready for use.

    Example:
        >>> engine = create_cli_engine("git", policy=ExecPolicy(timeout=60))
        >>> result = engine.run(CommandSpec(name="status", argv=["status"]))
    """
    resolved_policy = policy or ExecPolicy()
    return CliEngine(
        binary,
        policy=resolved_policy,
        renderer=renderer or DefaultCommandRenderer(),
        executor=executor or SubprocessExecutor(resolved_policy),
        parser=parser or DefaultOutputParser(),
        success_codes=success_codes,
    )
