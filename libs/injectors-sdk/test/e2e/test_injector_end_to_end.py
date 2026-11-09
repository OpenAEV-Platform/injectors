"""End-to-end tests of an injector run as a process, without the platform.

Feature: An injector runs end to end without the platform
  A lab injector, started as its own process with --dev, writes a lean inject message
  to edit, runs it, writes the calls the platform would have received, emits the
  pending expectations collectors would then get, and replays its outside calls offline
  with exactly the same result.
"""

import json
import subprocess
import sys
from pathlib import Path

from pydantic import TypeAdapter
from xtm_oaev_sdk import InjectExpectationOutput

LAB_INJECTOR = Path(__file__).parent / "lab_injector.py"
SECRET = "lab-secret-123"


def _when_starting(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    """When the lab injector starts as a process with "--dev <args>" """
    return subprocess.run(
        [sys.executable, str(LAB_INJECTOR), "--dev", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _given_inject_message(tmp_path: Path) -> Path:
    """Given the message --new-inject writes for "ping", its ip filled with 10.0.0.7"""
    written = _when_starting(tmp_path, "--new-inject", "ping")
    assert written.returncode == 0, written.stderr
    message = json.loads(written.stdout)
    message["injection"]["inject_content"]["ip"] = "10.0.0.7"
    path = tmp_path / "inject.json"
    path.write_text(json.dumps(message))
    return path


def test_an_injector_process_emits_what_collectors_read(tmp_path: Path) -> None:
    """It writes the calls to --out and the pending expectations on stdout.

    Scenario: An injector process emits what collectors read
      Given the message --new-inject writes for "ping", its ip filled with 10.0.0.7
      When the lab injector starts as a process with "--dev --inject inject.json --emit expectations --out run.json"
      Then it exits with code 0
      And run.json holds the reception, the signatures and the complete callbacks, secrets redacted
      And stdout is the list of pending expectations a collector reads, signed with 10.0.0.7
    """
    message = _given_inject_message(tmp_path)
    run = _when_starting(
        tmp_path,
        "--inject",
        str(message),
        "--emit",
        "expectations",
        "--out",
        "run.json",
    )
    assert run.returncode == 0, run.stderr
    calls = json.loads((tmp_path / "run.json").read_text())
    assert [c["path"].rsplit("/", 2)[-2] for c in calls] == [
        "reception",
        "callback",
        "callback",
    ]
    assert SECRET not in (tmp_path / "run.json").read_text()
    pending = TypeAdapter(list[InjectExpectationOutput]).validate_json(run.stdout)
    assert [
        [(s.type, s.value) for s in e.inject_expectation_signatures] for e in pending
    ] == [[("target_ipv4_address", "10.0.0.7")]]


def test_an_injector_process_replays_its_run_offline(tmp_path: Path) -> None:
    """It replays a recorded run offline and writes exactly the same calls.

    Scenario: An injector process replays its run offline
      Given the message --new-inject writes for "ping", its ip filled with 10.0.0.7
      And the lab injector ran it with "--record lab.tape.json --out recorded.json"
      When the lab injector runs it with "--replay lab.tape.json --out replayed.json"
      Then replayed.json is byte for byte recorded.json
      And the tape lints clean, knowing the secret
    """
    message = _given_inject_message(tmp_path)
    recorded = _when_starting(
        tmp_path,
        "--inject",
        str(message),
        "--record",
        "lab.tape.json",
        "--out",
        "recorded.json",
    )
    replayed = _when_starting(
        tmp_path,
        "--inject",
        str(message),
        "--replay",
        "lab.tape.json",
        "--out",
        "replayed.json",
    )
    assert (recorded.returncode, replayed.returncode) == (0, 0), replayed.stderr
    assert (tmp_path / "replayed.json").read_bytes() == (
        tmp_path / "recorded.json"
    ).read_bytes()
    lint = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, xtm_oaev_sdk; print(xtm_oaev_sdk.lint_tape(sys.argv[1],"
            " [sys.argv[2]]))",
            str(tmp_path / "lab.tape.json"),
            SECRET,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert lint.stdout.strip() == "[]", lint.stdout + lint.stderr
