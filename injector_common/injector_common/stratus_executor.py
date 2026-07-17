"""Shared wrapper around the Stratus Red Team CLI.

Stratus Red Team (https://stratus-red-team.cloud) is a single self-contained Go
binary that emulates granular adversary techniques against AWS, Azure, GCP and
Kubernetes. This wrapper lives in ``injector_common`` so any Stratus-based
injector can reuse the detonation lifecycle; today it backs the GCP injector,
and it is designed so that future cloud injectors (e.g. Azure, Kubernetes) only
provide the platform, the technique catalog and the credential wiring.

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
        # Explicit None check so a caller can intentionally pass a falsy
        # timeout (e.g. 0) without it being replaced by the default.
        if timeout is None:
            timeout = self.DEFAULT_TIMEOUT_SECONDS
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
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
            # e.g. the binary exists but is not executable (PermissionError)
            # or has the wrong format; still surface a normalized result.
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
        except subprocess.TimeoutExpired:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message=f"Stratus cleanup for {technique_id} timed out",
            )
        except OSError as exc:
            # FileNotFoundError (missing binary) and other OSError cases such as
            # a non-executable binary must not break the always-returns-result
            # contract of the wrapper.
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message=f"Failed to execute stratus cleanup: {exc}",
            )
        success = result.returncode == 0
        # Stratus can exit without writing to stdout/stderr; fall back to a
        # deterministic message so downstream callbacks stay interpretable.
        message = (result.stderr or result.stdout or "").strip()[:500]
        if not message:
            message = (
                f"Cleaned up {technique_id}"
                if success
                else f"Stratus cleanup failed for {technique_id}"
            )
        return StratusResult(
            success=success,
            technique_id=technique_id,
            status="CLEAN" if success else "ERROR",
            message=message,
            stdout=result.stdout,
            stderr=result.stderr,
        )
