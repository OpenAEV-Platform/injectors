"""Runs the BloodHound.py (SharpHound-compatible) AD collector and parses it.

Collects Active Directory objects via `bloodhound-python` and turns the emitted
JSON into OpenAEV findings (users, computers) plus counts that surface the
attack surface. Kerberoastable / AS-REP-roastable accounts are flagged as
privilege-route findings.
"""

import glob
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class BloodhoundResult:
    success: bool
    message: str
    outputs: Dict[str, List[str]] = field(default_factory=dict)


class BloodhoundExecutor:
    DEFAULT_TIMEOUT_SECONDS = 900

    def __init__(self, logger=None):
        self.logger = logger

    def run_collection(
        self,
        domain: str,
        username: str,
        password: str,
        domain_controller: str,
    ) -> BloodhoundResult:
        with tempfile.TemporaryDirectory() as workdir:
            cmd = [
                "bloodhound-python",
                "-d",
                domain,
                "-u",
                username,
                "-p",
                password,
                "-dc",
                domain_controller,
                "-c",
                "All",
                "--zip",
            ]
            try:
                self._run(cmd, workdir)
            except subprocess.TimeoutExpired:
                return BloodhoundResult(
                    False, f"BloodHound collection timed out for {domain}"
                )
            except FileNotFoundError:
                return BloodhoundResult(
                    False, "bloodhound-python not found in the image"
                )

            outputs = self.parse_collection(workdir)

        users = outputs.get("users", [])
        computers = outputs.get("computers", [])
        return BloodhoundResult(
            success=True,
            message=(
                f"Collected {len(users)} users and {len(computers)} computers "
                f"from {domain}"
            ),
            outputs=outputs,
        )

    def _run(self, cmd: List[str], cwd: str) -> subprocess.CompletedProcess:
        if self.logger:
            # Never log the password argument.
            safe = [a if a != cmd[cmd.index("-p") + 1] else "***" for a in cmd]
            self.logger.info(f"Executing: {' '.join(safe)}")
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.DEFAULT_TIMEOUT_SECONDS,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
        )

    @staticmethod
    def parse_collection(workdir: str) -> Dict[str, List[str]]:
        outputs: Dict[str, List[str]] = {}
        outputs["users"] = BloodhoundExecutor._names(workdir, "*_users.json")
        outputs["computers"] = BloodhoundExecutor._names(workdir, "*_computers.json")
        privileged = BloodhoundExecutor._privileged(workdir)
        if privileged:
            outputs["attack_paths"] = privileged
        return {k: v for k, v in outputs.items() if v}

    @staticmethod
    def _load(path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _names(workdir: str, pattern: str) -> List[str]:
        names: List[str] = []
        for path in glob.glob(os.path.join(workdir, pattern)):
            data = BloodhoundExecutor._load(path)
            for entry in data.get("data", []):
                properties = entry.get("Properties", {})
                name = properties.get("name") or properties.get("samaccountname")
                if name and name not in names:
                    names.append(name)
        return names

    @staticmethod
    def _privileged(workdir: str) -> List[str]:
        paths: List[str] = []
        for path in glob.glob(os.path.join(workdir, "*_users.json")):
            data = BloodhoundExecutor._load(path)
            for entry in data.get("data", []):
                properties = entry.get("Properties", {})
                name = properties.get("name", "unknown")
                if properties.get("hasspn"):
                    paths.append(f"Kerberoastable: {name}")
                if properties.get("dontreqpreauth"):
                    paths.append(f"AS-REP roastable: {name}")
        return paths
