"""Subprocess-backed command executor implementation."""

import os
import platform
import shutil
import subprocess as _subprocess
import warnings

from injectors_second_sdk._core.cli_engine.contracts.exec_policy import ExecPolicy
from injectors_second_sdk._core.cli_engine.errors import (
    BinaryNotFoundError,
    CliContractError,
    CliExecutionError,
    ExecResult,
)

SHELL_METACHARS = "|;&$`><"


def _truncate_captured_output(output: str, max_output_bytes: int | None) -> str:
    if max_output_bytes is None:
        return output
    output_bytes = output.encode("utf-8")
    if len(output_bytes) <= max_output_bytes:
        return output
    return f"{output_bytes[:max_output_bytes].decode('utf-8', errors='ignore')}[truncated]"


def _decode_captured(value: str | bytes | None) -> str:
    """Safely decode captured output that may be str, bytes, or None."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


class SubprocessExecutor:
    """Execute argv commands using subprocess.run under a configurable policy.

    Attributes:
        policy: The execution policy governing timeout, env, shell mode, etc.
    """

    def __init__(self, policy: ExecPolicy | None = None) -> None:
        self.policy = policy or ExecPolicy()

    def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        stdin: str | bytes | None = None,
    ) -> ExecResult:
        """Execute a command and return structured results.

        Args:
            argv: Command-line arguments to execute.
            env: Per-call environment variable overrides.
            cwd: Working directory for this execution.
            stdin: Input to pass to the process stdin.

        Returns:
            An ExecResult with captured stdout, stderr, and exit code.

        Raises:
            CliContractError: On invalid argv, env, or shell metachar detection.
            CliExecutionError: On timeout.
            BinaryNotFoundError: When the binary cannot be found.
        """
        if not isinstance(argv, list) or any(not isinstance(arg, str) for arg in argv):
            raise CliContractError("argv must be a list of strings")
        if not argv:
            raise CliContractError("argv must not be empty")

        shell_resolved = (
            platform.system() == "Windows"
            if self.policy.shell == "auto"
            else bool(self.policy.shell)
        )

        if shell_resolved:
            warnings.warn(
                "ExecPolicy has shell=True. This bypasses argument safety.",
                UserWarning,
                stacklevel=2,
            )

        has_metachars = any(any(char in arg for char in SHELL_METACHARS) for arg in argv)
        if has_metachars:
            if shell_resolved:
                raise CliContractError(
                    "Shell metacharacters detected in argv while shell=True. "
                    "This is a command injection risk. Sanitize input or use shell=False."
                )
            warnings.warn(
                "Shell metacharacters detected in argv. This may indicate an injection risk.",
                UserWarning,
                stacklevel=2,
            )

        # Merge environment: os.environ + policy overrides + per-call env
        merged_env = os.environ.copy()
        merged_env.update(self.policy.env_overrides)
        if env is not None and (
            not isinstance(env, dict)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items())
        ):
            raise CliContractError("env must be a dict[str, str] or None")
        if env:
            merged_env.update(env)

        # Resolve binary existence
        binary = argv[0]
        if self.policy.check_binary_exists:
            resolved = shutil.which(binary, path=merged_env.get("PATH"))
            if resolved is None:
                raise BinaryNotFoundError(binary)

        # Resolve working directory
        if cwd is None and self.policy.working_directory is not None:
            cwd = str(self.policy.working_directory)
        if cwd is not None and not isinstance(cwd, str):
            raise CliContractError("cwd must be a string or None")

        # Shell mode: join argv into single string
        command: list[str] | str = argv
        if shell_resolved:
            command = " ".join(argv)

        if not self.policy.text and isinstance(stdin, str):
            raise CliContractError("stdin must be bytes when ExecPolicy.text is False")

        try:
            completed = _subprocess.run(
                command,
                shell=shell_resolved,
                timeout=self.policy.timeout,
                env=merged_env,
                cwd=cwd,
                capture_output=True,
                text=self.policy.text,
                input=stdin,
            )
        except _subprocess.TimeoutExpired as exc:
            raise CliExecutionError(
                ExecResult(
                    argv=list(argv),
                    returncode=124,
                    stdout=_decode_captured(exc.stdout),
                    stderr=_decode_captured(exc.stderr) or str(exc),
                )
            ) from exc
        except FileNotFoundError as exc:
            raise BinaryNotFoundError(binary) from exc

        result = ExecResult(
            argv=list(argv),
            returncode=completed.returncode,
            stdout=_truncate_captured_output(
                _decode_captured(completed.stdout),
                self.policy.max_output_bytes,
            ),
            stderr=_truncate_captured_output(
                _decode_captured(completed.stderr),
                self.policy.max_output_bytes,
            ),
        )
        return result
