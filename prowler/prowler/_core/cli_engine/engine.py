"""Ordered CLI-engine orchestration."""

from dataclasses import replace

from .contracts import (CommandResult, ExecutionSpecification,
                        ValidatedCommandRequest)
from .errors import ExecutionError, ParsingError
from .ports import (BinaryResolverPort, ExecutorPort, OutputParserPort,
                    PolicyPort)


class CliEngine:
    """Run policy, resolution validation, execution, then parsing."""

    def __init__(
        self,
        *,
        policy: PolicyPort,
        resolver: BinaryResolverPort,
        executor: ExecutorPort,
        parser: OutputParserPort,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._executor = executor
        self._parser = parser

    def run(self, request: ValidatedCommandRequest) -> CommandResult:
        """Return all expected outcomes in one envelope."""
        specification = ExecutionSpecification.from_request(request)
        policy_error = self._policy.check(specification)
        if policy_error is not None:
            return CommandResult(specification, error=policy_error)
        resolution_error = self._resolver.validate(specification)
        if resolution_error is not None:
            return CommandResult(specification, error=resolution_error)
        execution = self._executor.execute(specification)
        if isinstance(execution, ExecutionError):
            return CommandResult(
                specification,
                stdout=execution.stdout,
                stderr=execution.stderr,
                return_code=execution.return_code,
                error=execution,
            )
        result = CommandResult(
            specification,
            stdout=execution.stdout,
            stderr=execution.stderr,
            return_code=execution.return_code,
        )
        if execution.return_code != 0:
            return replace(
                result,
                error=ExecutionError(
                    "process returned an unsuccessful outcome",
                    kind="unsuccessful_process",
                    stdout=execution.stdout,
                    stderr=execution.stderr,
                    return_code=execution.return_code,
                ),
            )
        if (
            max(len(execution.stdout), len(execution.stderr))
            > specification.maximum_accepted_output_bytes
        ):
            return replace(
                result,
                error=ExecutionError(
                    "captured process output exceeds the accepted size",
                    kind="output_too_large_after_capture",
                    stdout=execution.stdout,
                    stderr=execution.stderr,
                    return_code=execution.return_code,
                ),
            )
        parsed = self._parser.parse(specification, execution.stdout)
        if isinstance(parsed, ParsingError):
            owned_error = ParsingError(
                parsed.message,
                kind=parsed.kind,
                stdout=execution.stdout,
                stderr=execution.stderr,
                context=parsed.context,
                cause=parsed.cause,
            )
            return replace(result, error=owned_error)
        return replace(result, parsed=parsed)
