"""Promptfoo engine: wraps the Promptfoo red-team CLI (https://promptfoo.dev) for declarative
plugin/strategy red-teaming with assertion-based pass/fail. Promptfoo is a Node CLI and must be
available in the injector image; otherwise a clear ERROR is returned."""

import json
import os
import shutil
import subprocess
import tempfile

import yaml

from ai_redteam.contracts import constants as c
from ai_redteam.engines.base import Engine, EngineResult


def _provider_config(target):
    provider = target.provider
    if provider in (
        "OPENAI_COMPATIBLE",
        "AZURE_OPENAI",
        "AWS_BEDROCK",
        "GOOGLE_VERTEX",
    ):
        cfg = {"id": f"openai:chat:{target.model or 'gpt-4o-mini'}", "config": {}}
        if target.endpoint:
            cfg["config"]["apiBaseUrl"] = target.endpoint
        if target.api_key:
            cfg["config"]["apiKey"] = target.api_key
        return cfg
    if provider == "ANTHROPIC":
        cfg = {
            "id": f"anthropic:messages:{target.model or 'claude-3-5-sonnet-latest'}",
            "config": {},
        }
        if target.api_key:
            cfg["config"]["apiKey"] = target.api_key
        return cfg
    if provider == "OLLAMA":
        return {"id": f"ollama:chat:{target.model or 'llama3'}"}
    # Generic HTTP provider
    return {
        "id": "https",
        "config": {
            "url": target.endpoint or "",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": {"input": "{{prompt}}"},
        },
    }


class PromptfooEngine(Engine):
    def __init__(self, timeout=900):
        self.timeout = max(timeout, 600)

    def run(self, content, target, marker, ctx) -> EngineResult:
        if shutil.which("promptfoo") is None:
            return EngineResult(
                success=False,
                status="ERROR",
                message="Promptfoo is not installed in this injector image (npm i -g promptfoo).",
            )

        plugins = [
            p.strip()
            for p in (content.get(c.KEY_PROMPTFOO_PLUGINS) or "prompt-injection").split(
                ","
            )
            if p.strip()
        ]
        strategies = [
            s.strip()
            for s in (content.get(c.KEY_PROMPTFOO_STRATEGIES) or "jailbreak").split(",")
            if s.strip()
        ]

        workdir = tempfile.mkdtemp(prefix="promptfoo_")
        try:
            config_path = os.path.join(workdir, "promptfooconfig.yaml")
            output_path = os.path.join(workdir, "results.json")
            config = {
                "providers": [_provider_config(target)],
                "redteam": {
                    "plugins": plugins,
                    "strategies": strategies,
                    "purpose": "OpenAEV adversarial exposure validation",
                },
            }
            with open(config_path, "w", encoding="utf-8") as handle:
                yaml.safe_dump(config, handle)

            try:
                gen = subprocess.run(
                    [
                        "promptfoo",
                        "redteam",
                        "generate",
                        "-c",
                        config_path,
                        "-o",
                        os.path.join(workdir, "redteam.yaml"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=workdir,
                    check=False,
                )
                run = subprocess.run(
                    [
                        "promptfoo",
                        "redteam",
                        "run",
                        "-c",
                        config_path,
                        "--output",
                        output_path,
                        "--no-cache",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    cwd=workdir,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return EngineResult(
                    success=False,
                    status="ERROR",
                    message=f"Promptfoo timed out after {self.timeout}s",
                )

            successes, failures = self._parse_results(output_path)
            vulnerable = failures > 0
            outputs = {
                "marker": marker,
                "target_endpoint": target.endpoint or "",
                "promptfoo_plugins": ",".join(plugins),
                "promptfoo_strategies": ",".join(strategies),
                "promptfoo_failures": failures,
                "promptfoo_passes": successes,
                "attack_succeeded": vulnerable,
            }
            if vulnerable:
                outputs["vulnerability"] = [
                    {
                        "value": f"Promptfoo red-team found {failures} failing assertion(s)",
                        "reason": "Assertion failed",
                    }
                ]
            message = (
                f"[{'VULNERABLE' if vulnerable else 'DEFENDED'}] Promptfoo red-team: "
                f"{failures} failed / {successes} passed assertions.\n"
                f"Plugins: {plugins} | Strategies: {strategies}\n"
                f"{(run.stdout or gen.stdout or '')[-1500:]}"
            )
            return EngineResult(
                success=vulnerable, status="SUCCESS", message=message, outputs=outputs
            )
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @staticmethod
    def _parse_results(output_path):
        successes = 0
        failures = 0
        if not os.path.exists(output_path):
            return successes, failures
        try:
            with open(output_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (ValueError, OSError):
            return successes, failures
        results = data.get("results", {})
        # promptfoo output schema: results.stats.{successes,failures} or results.results[].success
        stats = results.get("stats") if isinstance(results, dict) else None
        if isinstance(stats, dict):
            return int(stats.get("successes", 0)), int(stats.get("failures", 0))
        rows = results.get("results", []) if isinstance(results, dict) else []
        for row in rows:
            if row.get("success"):
                successes += 1
            else:
                failures += 1
        return successes, failures
