"""Garak engine: wraps NVIDIA Garak (https://github.com/NVIDIA/garak), a broad LLM vulnerability
scanner with 120+ probes. Runs garak as a subprocess against the target and parses its JSONL report.

Garak must be installed in the injector image (the Dockerfile installs it). If it is not available,
a clear ERROR result is returned rather than silently degrading."""

import json
import os
import shutil
import subprocess
import tempfile

from ai_redteam.contracts import constants as c
from ai_redteam.engines.base import Engine, EngineResult


def _model_type_and_env(target):
    env = dict(os.environ)
    provider = target.provider
    if provider in (
        "OPENAI_COMPATIBLE",
        "AZURE_OPENAI",
        "AWS_BEDROCK",
        "GOOGLE_VERTEX",
    ):
        if target.api_key:
            env["OPENAI_API_KEY"] = target.api_key
        if target.endpoint:
            env["OPENAI_API_BASE"] = target.endpoint
            env["OPENAI_BASE_URL"] = target.endpoint
        return "openai", target.model or "gpt-4o-mini", env
    if provider == "OLLAMA":
        return "ollama", target.model or "llama3", env
    if provider == "HUGGINGFACE":
        if target.api_key:
            env["HF_INFERENCE_TOKEN"] = target.api_key
        return "huggingface", target.model or "", env
    # Fallback: treat as OpenAI-compatible
    if target.api_key:
        env["OPENAI_API_KEY"] = target.api_key
    if target.endpoint:
        env["OPENAI_API_BASE"] = target.endpoint
    return "openai", target.model or "gpt-4o-mini", env


class GarakEngine(Engine):
    def __init__(self, timeout=600):
        self.timeout = max(timeout, 600)

    def run(self, content, target, marker, ctx) -> EngineResult:
        if shutil.which("garak") is None:
            return EngineResult(
                success=False,
                status="ERROR",
                message="Garak is not installed in this injector image (pip install garak).",
            )

        probes = content.get(c.KEY_GARAK_PROBES) or "promptinject"
        generations = content.get(c.KEY_GARAK_GENERATIONS) or "3"
        model_type, model_name, env = _model_type_and_env(target)

        workdir = tempfile.mkdtemp(prefix="garak_")
        try:
            prefix = os.path.join(workdir, "scan")
            cmd = [
                "garak",
                "--model_type",
                model_type,
                "--model_name",
                model_name,
                "--probes",
                probes,
                "--generations",
                str(generations),
                "--report_prefix",
                prefix,
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    env=env,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return EngineResult(
                    success=False,
                    status="ERROR",
                    message=f"Garak timed out after {self.timeout}s",
                )

            report_path = f"{prefix}.report.jsonl"
            passed, total, failed_probes = self._parse_report(report_path)
            vulnerable = total > 0 and passed < total
            outputs = {
                "marker": marker,
                "target_endpoint": target.endpoint or "",
                "garak_probes": probes,
                "garak_passed": passed,
                "garak_total": total,
                "attack_succeeded": vulnerable,
            }
            if vulnerable:
                outputs["vulnerability"] = [
                    {
                        "value": f"Garak probe failed: {p}",
                        "reason": "Detector triggered",
                    }
                    for p in failed_probes[:50]
                ]
            message = (
                f"[{'VULNERABLE' if vulnerable else 'DEFENDED'}] Garak scan complete: "
                f"{total - passed}/{total} checks failed across probes [{probes}].\n"
                f"Exit code: {proc.returncode}\n"
                f"{(proc.stdout or '')[-1500:]}"
            )
            return EngineResult(
                success=vulnerable, status="SUCCESS", message=message, outputs=outputs
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _parse_report(report_path):
        passed = 0
        total = 0
        failed_probes = []
        if not os.path.exists(report_path):
            return passed, total, failed_probes
        with open(report_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if entry.get("entry_type") == "eval":
                    entry_total = int(entry.get("total", 0))
                    entry_passed = int(entry.get("passed", 0))
                    total += entry_total
                    passed += entry_passed
                    if entry_passed < entry_total:
                        failed_probes.append(entry.get("probe", "unknown"))
        return passed, total, failed_probes
