"""Safe subprocess execution adapter."""

import subprocess

from pydantic import SecretStr

from ..contracts import ExecutionSpecification, ProcessOutcome
from ..errors import ExecutionError


class SubprocessExecutor:
    """Execute structured argv with shell disabled."""

    def execute(
        self, specification: ExecutionSpecification
    ) -> ProcessOutcome | ExecutionError:
        """Capture exact bytes and envelope startup and timeout failures."""
        environment = {
            name: value.get_secret_value() if isinstance(value, SecretStr) else value
            for name, value in specification.environment
        }
        try:
            completed = subprocess.run(  # noqa: S603 - policy-approved structured argv
                specification.argv,
                input=specification.input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=specification.working_directory,
                env=environment,
                timeout=specification.timeout_seconds,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return ExecutionError(
                "process timed out",
                kind="timeout",
                stdout=error.output or b"",
                stderr=error.stderr or b"",
                cause=type(error).__name__,
            )
        except OSError as error:
            return ExecutionError(
                "process could not be started",
                kind="process_start_failed",
                cause=type(error).__name__,
            )
        return ProcessOutcome(completed.returncode, completed.stdout, completed.stderr)
