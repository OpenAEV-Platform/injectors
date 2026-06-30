"""Execution policy configuration for command execution."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecPolicy(BaseModel):
    """Configuration values used by command execution adapters.

    Attributes:
        shell: Whether to use shell execution (bool or "auto" for platform detection).
        acknowledge_shell_risk: Must be True when shell=True (security opt-in).
        timeout: Maximum seconds to wait for command completion.
        retries: Number of retry attempts (currently a no-op placeholder).
        check_binary_exists: Whether to verify binary reachability before execution.
        env_overrides: Environment variables to merge on top of os.environ.
        working_directory: Default working directory for command execution.
        max_output_bytes: Maximum bytes to capture from stdout/stderr (None=unlimited).
        text: Whether to capture output in text mode (True) or binary mode (False).
    """

    model_config = ConfigDict(extra="forbid")

    shell: bool | str = False
    acknowledge_shell_risk: bool = False
    timeout: int = Field(default=30, ge=1)
    retries: int = Field(default=0, ge=0)
    check_binary_exists: bool = True
    env_overrides: dict[str, str] = Field(default_factory=dict)
    working_directory: str | Path | None = None
    max_output_bytes: int | None = Field(default=None, ge=1)
    text: bool = True

    @model_validator(mode="after")
    def validate_shell_risk_acknowledgement(self) -> "ExecPolicy":
        """Validate shell mode configuration."""
        if isinstance(self.shell, str) and self.shell != "auto":
            raise ValueError("shell accepts only bool or the string 'auto'")
        if self.shell and not self.acknowledge_shell_risk:
            raise ValueError("shell=True requires acknowledge_shell_risk=True")
        return self


__all__ = ["ExecPolicy"]
