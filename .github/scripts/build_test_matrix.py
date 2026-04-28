#!/usr/bin/env python3
"""
Generate the GitHub Actions test matrix for injector tests.

Discovers all injectors with test directories (test/ or tests/) and
includes them in the matrix. All injectors are always tested.
"""

import json
import os
from pathlib import Path

# Directories that are NOT injectors (excluded from discovery)
EXCLUDED_DIRS = {
    ".circleci",
    ".github",
    "scripts",
    ".git",
    "__pycache__",
    "node_modules",
}


def discover_injectors() -> list[str]:
    """Find all injector directories that contain test/ or tests/ subdirectories."""
    injectors = []
    for entry in sorted(Path(".").iterdir()):
        if (
            not entry.is_dir()
            or entry.name.startswith(".")
            or entry.name in EXCLUDED_DIRS
        ):
            continue
        if (entry / "test").is_dir() or (entry / "tests").is_dir():
            injectors.append(entry.name)
    return injectors


def write_output(key: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    line = f"{key}={value}\n"
    if output_file:
        with Path(output_file).open("a") as f:
            f.write(line)
    else:
        print(line, end="")


def main() -> None:
    all_injectors = discover_injectors()
    print(f"Total injectors with tests: {len(all_injectors)}")

    for i in all_injectors:
        print(f"  - {i}")

    if not all_injectors:
        print("No injectors to test.")
        write_output("has_tests", "false")
        write_output("matrix", json.dumps({"include": []}, separators=(",", ":")))
        return

    entries = [{"name": i, "injector": i} for i in all_injectors]
    write_output("has_tests", "true")
    write_output("matrix", json.dumps({"include": entries}, separators=(",", ":")))


if __name__ == "__main__":
    main()
