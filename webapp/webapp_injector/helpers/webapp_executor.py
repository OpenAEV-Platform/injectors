"""Wraps OWASP ZAP (baseline) and SQLMap for active web-application testing."""

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


@dataclass
class WebappResult:
    success: bool
    message: str
    outputs: Dict[str, List[str]] = field(default_factory=dict)


class WebappExecutor:
    DEFAULT_TIMEOUT_SECONDS = 900
    STDERR_EXCERPT_CHARS = 500

    def __init__(self, logger=None):
        self.logger = logger

    @staticmethod
    def _trim_stderr(stderr: str) -> str:
        excerpt = (stderr or "").strip()
        if len(excerpt) > WebappExecutor.STDERR_EXCERPT_CHARS:
            excerpt = excerpt[-WebappExecutor.STDERR_EXCERPT_CHARS :]
        return excerpt

    def _run(self, cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
        if self.logger:
            self.logger.info(f"Executing: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

    def run_zap_baseline(self, target_url: str) -> WebappResult:
        """Run the ZAP baseline scan and parse its JSON report into findings."""
        with tempfile.TemporaryDirectory() as workdir:
            report = Path(workdir) / "zap.json"
            cmd = [
                "zap-baseline.py",
                "-t",
                target_url,
                "-J",
                str(report),
                "-I",
            ]
            try:
                self._run(cmd, self.DEFAULT_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                return WebappResult(False, f"ZAP baseline timed out for {target_url}")
            except FileNotFoundError:
                return WebappResult(False, "zap-baseline.py not found in the image")

            if not report.exists():
                return WebappResult(False, f"ZAP produced no report for {target_url}")
            alerts = self._parse_zap_report(report.read_text(encoding="utf-8"))

        return WebappResult(
            success=True,
            message=f"ZAP baseline found {len(alerts)} alert(s) on {target_url}",
            outputs={"vulnerabilities": alerts},
        )

    @staticmethod
    def _parse_zap_report(raw: str) -> List[str]:
        try:
            report = json.loads(raw)
        except json.JSONDecodeError:
            return []
        alerts = []
        for site in report.get("site", []):
            for alert in site.get("alerts", []):
                name = alert.get("alert") or alert.get("name")
                if name and name not in alerts:
                    alerts.append(name)
        return alerts

    def run_sqlmap(self, target_url: str) -> WebappResult:
        """Run SQLMap against a target URL and report injectable parameters."""
        cmd = [
            "sqlmap",
            "-u",
            target_url,
            "--batch",
            "--level=1",
            "--risk=1",
            "--disable-coloring",
        ]
        try:
            result = self._run(cmd, self.DEFAULT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return WebappResult(False, f"SQLMap timed out for {target_url}")
        except FileNotFoundError:
            return WebappResult(False, "sqlmap not found in the image")

        if result.returncode != 0:
            excerpt = self._trim_stderr(result.stderr)
            message = f"SQLMap failed for {target_url} (exit {result.returncode})"
            if excerpt:
                message = f"{message}: {excerpt}"
            return WebappResult(False, message)

        vulnerabilities = self._parse_sqlmap(result.stdout or "")
        return WebappResult(
            success=True,
            message=(
                f"SQLMap found {len(vulnerabilities)} injectable parameter(s) on "
                f"{target_url}"
            ),
            outputs={"vulnerabilities": vulnerabilities},
        )

    @staticmethod
    def _parse_sqlmap(stdout: str) -> List[str]:
        vulnerabilities = []
        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Parameter:") and stripped not in vulnerabilities:
                vulnerabilities.append(stripped)
        return vulnerabilities
