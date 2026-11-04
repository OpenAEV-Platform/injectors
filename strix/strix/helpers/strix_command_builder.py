"""Builds the ``strix`` command line for one inject.

Only orchestration flags are set here (targets, scan depth, run bounds,
non-interactive mode). The offensive behavior lives entirely in the Strix tool
itself; this builder never generates payloads or exploit content.
"""

from typing import List


class StrixCommandBuilder:
    VALID_SCAN_MODES = {"quick", "standard", "deep"}

    def __init__(self, strix_configs, content: dict, targets: List[str]):
        self.args: List[str] = []
        self.strix_configs = strix_configs
        self.content = content or {}
        self.targets = targets

    def build(self) -> List[str]:
        self.args = ["strix", "--non-interactive"]
        self._with_targets()
        self._with_scan_mode()
        self._with_run_bounds()
        self._with_instruction()
        return list(self.args)

    def _with_targets(self):
        for target in self.targets:
            target = str(target).strip()
            if target:
                self.args += ["--target", target]
        return self

    def _resolve_scan_mode(self) -> str:
        # A per-inject override wins over the injector default; the contract
        # select can arrive as a str or a single-element list.
        override = self.content.get("scan_mode")
        if isinstance(override, list):
            override = override[0] if override else None
        if isinstance(override, str) and override.strip().lower() in self.VALID_SCAN_MODES:
            return override.strip().lower()
        return self.strix_configs.scan_mode

    def _with_scan_mode(self):
        self.args += ["--scan-mode", self._resolve_scan_mode()]
        return self

    def _with_run_bounds(self):
        # Bound the run so a "deep" assessment cannot spin without limit.
        self.args += ["--max-turns", str(self.strix_configs.max_turns)]
        if self.strix_configs.max_budget_usd:
            self.args += ["--max-budget", str(self.strix_configs.max_budget_usd)]
        return self

    def _with_instruction(self):
        instruction = self.content.get("instruction")
        if isinstance(instruction, str) and instruction.strip():
            self.args += ["--instruction", instruction.strip()]
        return self
