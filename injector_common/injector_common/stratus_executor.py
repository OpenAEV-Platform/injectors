"""Shared wrapper around the Stratus Red Team CLI.

Stratus Red Team (https://stratus-red-team.cloud) is a single self-contained Go
binary that emulates granular adversary techniques against AWS, Azure, Entra ID,
GCP, Kubernetes and EKS. This helper is shared by the Stratus injector: the
injector only provides the platform, the technique catalog and the credential
wiring, while the detonation lifecycle lives here.

The executor never raises for an expected tool failure; it always returns a
StratusResult so the calling injector can turn it into an execution callback.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Host variables through which the cloud SDKs and Terraform providers driven by
# Stratus pick up credentials (or the project / subscription they apply to).
HOST_CREDENTIAL_ENV_PREFIXES = (
    "AWS_",
    "AZURE_",
    "ARM_",
    "GOOGLE_",
    "GCLOUD_",
    "CLOUDSDK_",
    "KUBECONFIG",
)


def _is_host_credential_variable(name: str) -> bool:
    # Environment variable names are case-insensitive on Windows.
    return name.upper().startswith(HOST_CREDENTIAL_ENV_PREFIXES)


# Stratus logs to stdout with the Go standard prefix ("2006/01/02 15:04:05 ").
# Before warming up or detonating it prints the line below once per platform,
# then either continues silently (passed) or exits through log.Fatal with one
# of the messages listed after it (cmd/stratus/util.go, pkg/stratus/providers.go
# and internal/providers/*.go in Stratus Red Team v2).
_GO_LOG_PREFIX = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ")
_AUTH_CHECK_LINE = re.compile(r"^Checking your authentication against (\S+)$")
AUTH_FAILURE_PREFIXES = (
    "you are not authenticated against",
    "You do not have a kubeconfig set up",
    "AZURE_SUBSCRIPTION_ID is not set",
    "unable to load AWS configuration",
    "unable to build kube config",
)

AUTH_PASSED = "passed"
AUTH_FAILED = "failed"


def _log_lines(output: str) -> List[str]:
    """Return the non-empty output lines without their Go log prefix."""
    lines = (_GO_LOG_PREFIX.sub("", line).strip() for line in output.splitlines())
    return [line for line in lines if line]


def parse_authentication(
    output: str, returncode: int
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Read the outcome of the Stratus authentication check from its output.

    Returns ``(platform, status, failure)``: the platform as named by Stratus
    (``AWS``, ``EKS``, ``azure``, ``entra-id``, ``GCP``, ``kubernetes``), the
    ``AUTH_PASSED`` / ``AUTH_FAILED`` status, and the first line of the
    failure message. All three are ``None`` when Stratus never reached the
    check. The check passed when Stratus went on after it: it exited with 0,
    or it printed further lines that are not an authentication failure.
    """
    lines = _log_lines(output)
    for index, line in enumerate(lines):
        match = _AUTH_CHECK_LINE.match(line)
        if match is None:
            continue
        platform = match.group(1)
        following = lines[index + 1 :]
        for next_line in following:
            if next_line.startswith(AUTH_FAILURE_PREFIXES):
                return platform, AUTH_FAILED, next_line
        if returncode == 0 or following:
            return platform, AUTH_PASSED, None
        return platform, AUTH_FAILED, None
    return None, None, None


@dataclass
class StratusResult:
    """Normalized result of a Stratus command."""

    success: bool
    technique_id: str
    status: str
    message: str
    stdout: str = ""
    stderr: str = ""
    # Outcome of the Stratus authentication check, see ``parse_authentication``.
    auth_platform: Optional[str] = None
    auth_status: Optional[str] = None
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
        isolate_host_credentials: bool = False,
    ) -> subprocess.CompletedProcess:
        cmd = [self.binary, *args]
        self._log("info", f"Executing: {' '.join(cmd)}")
        run_env = os.environ.copy()
        if isolate_host_credentials:
            run_env = {
                name: value
                for name, value in run_env.items()
                if not _is_host_credential_variable(name)
            }
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
        isolate_host_credentials: bool = False,
    ) -> StratusResult:
        """Warm up and detonate a technique, cleaning up infrastructure by default.

        ``--cleanup`` reverts the Terraform-provisioned prerequisites so a
        detonation never leaves live infrastructure behind.

        ``isolate_host_credentials`` drops the host cloud credential variables
        (see ``HOST_CREDENTIAL_ENV_PREFIXES``) before ``env`` is applied, so a
        host credential can never be combined with the one supplied in ``env``.
        """
        args = ["detonate", technique_id]
        if cleanup:
            args.append("--cleanup")

        try:
            result = self._run(
                args, env=env, isolate_host_credentials=isolate_host_credentials
            )
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

        auth_platform, auth_status, auth_failure = parse_authentication(
            result.stdout or "", result.returncode
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
                auth_platform=auth_platform,
                auth_status=auth_status,
            )

        if auth_status == AUTH_FAILED:
            message = f"Authentication against {auth_platform} failed" + (
                f": {auth_failure}" if auth_failure else ""
            )
        else:
            # Stratus logs to stdout and exits on its last line, so the tail of
            # the combined output carries the actual error.
            combined = "\n".join(
                part.strip() for part in (result.stdout, result.stderr) if part
            ).strip()
            message = combined[-500:] or f"Stratus failed for {technique_id}"
        return StratusResult(
            success=False,
            technique_id=technique_id,
            status="ERROR",
            message=message[:500],
            stdout=result.stdout,
            stderr=result.stderr,
            auth_platform=auth_platform,
            auth_status=auth_status,
        )

    def cleanup(
        self, technique_id: str, env: Optional[Dict[str, str]] = None
    ) -> StratusResult:
        """Best-effort teardown of a technique's prerequisite infrastructure.

        Normalizes execution failures the same way :meth:`detonate` does so
        cleanup results stay actionable and consistent across both commands.
        """
        try:
            result = self._run(["cleanup", technique_id], env=env)
        except subprocess.TimeoutExpired:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="TIMEOUT",
                message=f"Stratus cleanup for {technique_id} timed out",
            )
        except FileNotFoundError:
            return StratusResult(
                success=False,
                technique_id=technique_id,
                status="ERROR",
                message="stratus binary not found in the injector image",
            )
        except OSError as exc:
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
                status="CLEAN",
                message=f"Cleaned up {technique_id}",
                stdout=result.stdout,
                stderr=result.stderr,
            )

        error_detail = (result.stderr or result.stdout or "").strip()[:500]
        return StratusResult(
            success=False,
            technique_id=technique_id,
            status="ERROR",
            message=error_detail or f"Stratus cleanup failed for {technique_id}",
            stdout=result.stdout,
            stderr=result.stderr,
        )
