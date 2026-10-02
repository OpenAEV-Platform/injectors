"""Run the Strix CLI in an isolated per-inject working directory.

Strix writes its results under ``<cwd>/strix_runs/<run-name>/``; giving each
inject its own empty working directory makes the newest (and only) run there
unambiguous to locate afterwards.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class StrixRunResult:
    returncode: int
    stdout: str
    stderr: str
    run_dir: Optional[Path]


class StrixProcess:
    @staticmethod
    def build_env(strix_configs, llm_overrides: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Environment for the Strix subprocess (LLM provider + Docker host).

        ``llm_overrides`` carries per-inject values from the contract fields
        (llm_model, llm_api_base); when present and non-empty they take
        precedence over the injector defaults. The API key is intentionally
        NOT overridable per inject (no masked field type -> it would be stored
        in plaintext); it always comes from the injector configuration.
        """
        overrides = llm_overrides or {}
        model = overrides.get("llm_model") or strix_configs.llm_model
        api_base = overrides.get("llm_api_base") or strix_configs.llm_api_base
        env = os.environ.copy()
        env["STRIX_LLM"] = model
        if strix_configs.llm_api_key:
            env["LLM_API_KEY"] = strix_configs.llm_api_key
        if api_base:
            env["LLM_API_BASE"] = api_base
        if strix_configs.perplexity_api_key:
            env["PERPLEXITY_API_KEY"] = strix_configs.perplexity_api_key
        if strix_configs.docker_host:
            env["DOCKER_HOST"] = strix_configs.docker_host
        # Never let a TUI attach in a headless container.
        env.setdefault("STRIX_NON_INTERACTIVE", "1")
        return env

    @staticmethod
    def strix_version(timeout: int = 30) -> str:
        result = subprocess.run(
            ["strix", "--version"],
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        return result.stdout.decode("utf-8", "replace").strip()

    @staticmethod
    def _newest_run_dir(cwd: Path) -> Optional[Path]:
        runs_root = cwd / "strix_runs"
        if not runs_root.is_dir():
            return None
        candidates = [p for p in runs_root.iterdir() if p.is_dir()]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.stat().st_mtime)

    @staticmethod
    def execute(
        args: List[str],
        strix_configs,
        timeout: Optional[int],
        llm_overrides: Optional[Dict[str, str]] = None,
    ) -> StrixRunResult:
        """Run Strix to completion (or until *timeout*) and locate its run dir.

        Raises subprocess.TimeoutExpired on timeout (terminal). A non-zero exit
        is returned in the result (not raised) so the caller can best-effort
        parse any partial results Strix wrote before exiting.
        """
        Path(strix_configs.runs_root).mkdir(parents=True, exist_ok=True)
        cwd = Path(
            tempfile.mkdtemp(prefix="inject_", dir=strix_configs.runs_root)
        )
        env = StrixProcess.build_env(strix_configs, llm_overrides)
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
        )
        run_dir = StrixProcess._newest_run_dir(cwd)
        # Always return the result (including a non-zero return code). A non-zero
        # exit is NOT raised here: Strix can exit non-zero (e.g. MaxTurnsExceeded)
        # yet still have written partial results to run_dir. The caller decides
        # whether to surface those partials or treat it as a terminal error.
        # Only a timeout propagates (subprocess.run raises TimeoutExpired).
        return StrixRunResult(
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8", "replace"),
            stderr=completed.stderr.decode("utf-8", "replace"),
            run_dir=run_dir,
        )
