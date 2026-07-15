"""Shared wrapper around the Stratus Red Team CLI.

Stratus Red Team (https://stratus-red-team.cloud) is a single self-contained Go
binary that emulates granular adversary techniques against AWS, Azure, GCP and
Kubernetes. This helper is designed to be shared across Stratus-based injectors
(the kubernetes injector uses it today): each injector only provides the
platform, the technique catalog and the credential wiring, while the detonation
lifecycle lives here.

The executor never raises for an expected tool failure; it always returns a
StratusResult so the calling injector can turn it into an execution callback.
"""

import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class StratusResult:
    """Normalized result of a Stratus command."""

    success: bool
    technique_id: str
    status: str
    message: str
    stdout: str = ""
    stderr: str = ""
    # A detonation always emits exactly one technique, so the structured output
    # holds scalar values to match the single-cardinality contract outputs.
    outputs: Dict[str, str] = field(default_factory=dict)


class StratusExecutor:
    """Runs Stratus Red Team techniques through the ``stratus`` CLI."""

    # Attack lifecycle timeout: warm-up provisions cloud infrastructure via
    # Terraform, so detonation can legitimately take a few minutes.
    DEFAULT_TIMEOUT_SECONDS = 900

    def __init__(self, logger=None, binary: str = "stratus"):
        self.logger = logger
        self.binary = binary

    def _log(self, level: str, message: str) -> None:
        if self.logger is not None:
            getattr(self.logger, level)(message)

    def _run(
        self,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> subprocess.CompletedProcess:
        cmd = [self.binary, *args]
        self._log("info", f"Executing: {' '.join(cmd)}")
        run_env = os.environ.copy()
        if env:
            run_env.update({k: v for k, v in env.items() if v is not None})
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or self.DEFAULT_TIMEOUT_SECONDS,
            env=run_env,
            stdin=subprocess.DEVNULL,
        )

    def detonate(
        self,
        technique_id: str,
        env: Optional[Dict[str, str]] = None,
        cleanup: bool = True,
    ) -> StratusResult:
        """Warm up and detonate a technique, cleaning up infrastructure by default.

        ``--cleanup`` reverts the Terraform-provisioned prerequisites so a
        detonation never leaves live infrastructure behind.
        """
        args = ["detonate", technique_id]
        if cleanup:
            args.append("--cleanup")

        try:
            result = self._run(args, env=env)
        except subprocess.TimeoutExpired:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="TIMEOUT",
                message=f"Stratus technique {technique_id} timed out",
            )
        except FileNotFoundError:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message="stratus binary not found in the injector image",
            )
        except OSError as exc:
            # Any other OS-level execution failure (permission denied, exec
            # format error, ...). Keep the never-raises contract intact.
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message=f"Failed to execute stratus: {exc}",
            )

        if result.returncode == 0:
            return StratusResult(
                success=True,
                technique_id=technique_id,
                status="DETONATED",
                message=f"Detonated {technique_id}",
                stdout=result.stdout,
                stderr=result.stderr,
                outputs={"technique": technique_id},
            )

        error_detail = (result.stderr or result.stdout or "").strip()[:500]
        return StratusResult(
            success=False,
            technique_id=technique_id,
            status="ERROR",
            message=error_detail or f"Stratus failed for {technique_id}",
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def cleanup(
        self, technique_id: str, env: Optional[Dict[str, str]] = None
    ) -> StratusResult:
        """Best-effort teardown of a technique's prerequisite infrastructure."""
        try:
            result = self._run(["cleanup", technique_id], env=env)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message=str(exc),
            )
        return StratusResult(
            success=result.returncode == 0,
            technique_id=technique_id,
            status="CLEAN" if result.returncode == 0 else "ERROR",
            message=(result.stderr or result.stdout or "").strip()[:500],
            stdout=result.stdout,
            stderr=result.stderr,
        )
