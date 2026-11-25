"""Per-target reachability of a Nuclei scan.

Nuclei exits 0 when every request of a scan failed (unresolvable host, refused or
filtered port, host down, a host skipped by -max-host-error), so the exit code
alone cannot tell a target that answered without a match from a target the scan
never reached. With -matcher-status, Nuclei writes one JSONL event per request
outcome: a match (matcher-status true), a response without a match
(matcher-status false, no error) or a failed request (matcher-status false with
an "error" field). This module reads those events, and the host errors Nuclei
writes on stderr, into one verdict per target.
"""

import json
import re
import time
from typing import Dict, Iterable, Optional, Set
from urllib.parse import urlsplit

from injector_common.inject_gone import InjectGoneError, is_inject_gone

# Execution trace statuses of the platform (ExecutionTraceStatus): EXECUTED is a
# successful execution, ERROR a failed one.
REACHED_STATUS = "EXECUTED"
UNREACHED_STATUS = "ERROR"
# Unreached targets listed in the global message.
MAX_LISTED_TARGETS = 50

# A target the scan reached has no reason; any other gets one.
NO_RESPONSE_REASON = (
    "no response recorded (host unreachable, or no template request applied to it)"
)
MAX_REASON_LENGTH = 200

# "[WRN] [template-id] Skipped example.com:443 from target list as found
# unresponsive 30 times" (the -max-host-error skip).
_SKIPPED_RE = re.compile(
    r"Skipped (?P<host>\S+) from target list as found unresponsive(?P<rest>[^\n]*)"
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def normalize_host(value: Optional[str]) -> str:
    """The host name of a target or of a Nuclei event field, lower-cased, without
    scheme, credentials, port or path: 'https://Example.com:8443/x' -> 'example.com'.
    """
    if not value or not isinstance(value, str):
        return ""
    value = value.strip()
    if not value:
        return ""
    parsed = urlsplit(value if "://" in value else f"//{value}")
    try:
        host = parsed.hostname
    except ValueError:
        host = None
    return (host or "").lower()


def _event_hosts(event: dict) -> Set[str]:
    hosts = set()
    for key in ("host", "url", "matched-at", "ip"):
        host = normalize_host(event.get(key))
        if host:
            hosts.add(host)
    return hosts


def _cap(reason: str) -> str:
    reason = " ".join(reason.split())
    if len(reason) <= MAX_REASON_LENGTH:
        return reason
    return reason[: MAX_REASON_LENGTH - 3] + "..."


def assess_reachability(
    stdout: str, stderr: str, targets: Iterable[str]
) -> Dict[str, Optional[str]]:
    """One entry per target: None when the scan reached it (a match, or a response
    without a match), else the reason it was not reached (the first request error,
    the -max-host-error skip, or no response recorded at all)."""
    reached: Set[str] = set()
    errors: Dict[str, str] = {}
    stdout = stdout if isinstance(stdout, str) else ""
    stderr = stderr if isinstance(stderr, str) else ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        hosts = _event_hosts(event)
        error = event.get("error")
        if event.get("matcher-status") or not error:
            reached.update(hosts)
        else:
            for host in hosts:
                errors.setdefault(host, str(error))

    for line in _ANSI_RE.sub("", stderr).splitlines():
        match = _SKIPPED_RE.search(line)
        if match:
            host = normalize_host(match.group("host"))
            if host and host not in errors:
                errors[host] = "found unresponsive" + match.group("rest")

    verdicts: Dict[str, Optional[str]] = {}
    for target in targets:
        host = normalize_host(target)
        if host and host in reached:
            verdicts[target] = None
        else:
            verdicts[target] = _cap(errors.get(host) or NO_RESPONSE_REASON)
    return verdicts


def reachability_message(target: str, reason: Optional[str]) -> str:
    if reason is None:
        return f"nuclei scan reached target {target}"
    return f"nuclei scan: target {target} not reached: {reason}"


def unreached_summary(unreached: Dict[str, str], total: int) -> str:
    """'1/2 target(s) not reached', then one line per unreached target."""
    lines = [f"{len(unreached)}/{total} target(s) not reached"]
    for target, reason in list(unreached.items())[:MAX_LISTED_TARGETS]:
        lines.append(f"- {target}: {reason}")
    if len(unreached) > MAX_LISTED_TARGETS:
        lines.append(f"- and {len(unreached) - MAX_LISTED_TARGETS} more")
    return "\n".join(lines)


def send_reachability_traces(
    helper,
    inject_id: str,
    reachability: Dict[str, Optional[str]],
    ip_to_asset_id_map: Optional[Dict[str, Optional[str]]],
    start: float,
) -> None:
    """After the scan, one ``command_execution`` trace per asset-backed target with
    its real outcome, scoped to the asset through ``execution_context_identifiers``:
    EXECUTED when the scan reached it, ERROR with the reason when it did not, so the
    leaf of an unreached target is not proven executed. Targets without an asset id
    are listed in the global message only. A 404 (inject deleted) stops the loop."""
    if not ip_to_asset_id_map:
        return
    logger = helper.injector_logger
    duration = int(time.time() - start)
    sent = 0
    for target, reason in reachability.items():
        asset_id = ip_to_asset_id_map.get(target)
        if not asset_id:
            continue
        try:
            helper.api.inject.execution_callback(
                inject_id=inject_id,
                data={
                    "execution_message": reachability_message(target, reason),
                    "execution_status": (
                        REACHED_STATUS if reason is None else UNREACHED_STATUS
                    ),
                    "execution_duration": duration,
                    "execution_action": "command_execution",
                    "execution_context_identifiers": [asset_id],
                },
            )
            sent += 1
        except Exception as exc:  # noqa: BLE001
            if is_inject_gone(exc):
                raise InjectGoneError(inject_id, exc) from exc
            logger.error(
                f"Failed to send the reachability trace for inject {inject_id} "
                f"(target '{target}', asset {asset_id}): {exc}"
            )
    if sent:
        logger.info(f"Sent {sent} reachability trace(s) for inject {inject_id}")
